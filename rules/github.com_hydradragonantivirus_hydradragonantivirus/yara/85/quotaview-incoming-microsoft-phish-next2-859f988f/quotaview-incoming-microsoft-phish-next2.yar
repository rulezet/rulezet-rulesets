rule quotaview_incoming_microsoft_phish_next2 {
  meta:
    description = "microsoft-phish - file next2.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-08-11"
    hash1       = "1b17ccf2f6deaff79993028ddf843cc90367445d61a8f1d2acdeebe7fb38e4b8"

  strings:
    $s1  = "$message .= \"-----------  ! +Xoom LOGIN ! xDD+ !  -----------\\n\";" fullword ascii
    $s2  = "$headers = \"From: Herren <herren.ruth@gmail.com>\";" fullword ascii
    $s3  = "$message .= \"-----------  ! +Account infoS+ !  -----------\\n\";" fullword ascii
    $s4  = "$message .= \"Password : \".$_POST['pass'].\"\\n\";" fullword ascii
    $s5  = "$message .= \"-----------  ! +nJoY+ !  -----------\\n\";" fullword ascii
    $s6  = "$message .= \"Email : \".$_POST['userid'].\"\\n\";" fullword ascii
        $s8  = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
    $s9  = "header(\"Location: complete.php\");" fullword ascii
    $s10 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
    $s11 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
    $s12 = "mail($send,$subject,$message,$headers);" fullword ascii
    $s13 = "$message .= \"IP Address : \".$ip.\"\\n\";" fullword ascii
    $s14 = "$message .= \"CVV : \".$_POST['card_code'].\"\\n\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 2KB and
      (8 of them)
    ) or (all of them)
}