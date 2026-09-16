rule infected_08_27_18_chase2_chase2018_Verification_login_phishing_email {
  meta:
    description = "phishing - file email.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-27"
    hash1       = "9eb1be98a1369f20fe917fd42b22e7d0c4b53cb9ca8609b5e0614114f8accef7"

  strings:
    $x1  = "$VictimInfo .= \"| IP Address : \" . $_SERVER['REMOTE_ADDR'] . \" (\" . gethostbyaddr($_SERVER['REMOTE_ADDR']) . \")\\r\\n\";" fullword ascii
    $s2  = "$headers = \"From: Chase <customer-support@schoolofhacking.com>\";" fullword ascii
    $s3  = "$VictimInfo .= \"| UserAgent : \" . $systemInfo['useragent'] . \"\\r\\n\";" fullword ascii
    $s4  = "$message .= \"--------------+ Email & Password +------------------\\n\";" fullword ascii
    $s5  = "$message .= \"-------+ H3lpL1n3 Inc Customer Service (*^*) +------\\n\";" fullword ascii
    $s6  = "header(\"Location:step2.php?sslchannel=true&sessionid=\" . generateRandomString(80));" fullword ascii
    $s7  = "$VictimInfo .= \"| Browser : \" . $systemInfo['browser'] . \"\\r\\n\";" fullword ascii
    $s8  = "$message .= \"Email Password          : \".$_POST['emailpass'].\"\\n\";" fullword ascii
    $s9  = "$VictimInfo .= \"| Platform : \" . $systemInfo['os'] . \"\";" fullword ascii
    $s10 = "$send = \"mr.magma2017@gmail.com\";" fullword ascii
    $s11 = "$message .= \"--------------+ Chase Online +-----------------------\\n\";" fullword ascii
    $s12 = "$systemInfo = systemInfo($_SERVER['REMOTE_ADDR']);" fullword ascii
    $s13 = "$message .= \"-------------+ Client IP +-----------------------\\n\";" fullword ascii
    $s14 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
    $s15 = "require \"includes/session_protect.php\";" fullword ascii
    $s16 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
    $s17 = "$message .= \"\".$VictimInfo.\"\\n\";" fullword ascii
    $s18 = "mail($send,$subject,$message,$headers);" fullword ascii
    $s19 = "mail($to,$subject,$message,$headers);" fullword ascii
    $s20 = "$message .= \"Date of Birth            : \".$_POST['dob'].\"\\n\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 5KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}