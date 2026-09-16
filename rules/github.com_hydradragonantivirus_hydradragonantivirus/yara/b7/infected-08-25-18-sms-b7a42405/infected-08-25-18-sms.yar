rule infected_08_25_18_sms {
  meta:
    description = "entreeBam - file sms.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-25"
    hash1       = "d46fdda25dfa2de941727a2848716a6d0c840803d50d88003659c82452fe86fa"

  strings:
    $s1 = "$browser = getenv (\"HTTP_USER_AGENT\");" fullword ascii
        $s3 = "$message .= \"Certicode : \".$_POST['tel'].\"\\n\";" fullword ascii
    $s4 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
    $s5 = "header(\"Location: https://www.credit-agricole.fr/\");" fullword ascii
    $s6 = "$message .= \"-------------| ANASH  |-------------\\n\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}