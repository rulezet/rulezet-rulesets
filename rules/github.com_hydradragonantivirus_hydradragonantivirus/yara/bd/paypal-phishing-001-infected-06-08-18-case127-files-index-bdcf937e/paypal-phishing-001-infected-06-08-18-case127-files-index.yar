rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_index {
  meta:
    description = "case127 - file index.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "69ca1894b81eb9f09c5b13e087123901bb27fde0bd5df09b637e2a80a3f720cb"

  strings:
    $s1  = "<meta http-equiv=\"Description\" content=\" notneeded \"><!--googleon: all--><!--googleoff: all-->" fullword ascii
    $s2  = "<meta http-equiv=\"Keywords\" content=\" notneeded \"><!--googleon: all--><!--googleoff: all-->" fullword ascii
    $s3  = "fwrite($file,$ip.\"  -  \".gmdate (\"Y-n-d\").\" @ \".gmdate (\"H:i:s\").\"\\n\");" fullword ascii
    $s4  = "<meta http-equiv=\"refresh\" content=\"0; URL=Connexion.php?#/_flow&SESSION=PnlUc3mEHJJHI55454Op215LMp87878ijQ9wUub3cFpG7mo2DssM" ascii
    $s5  = "<meta http-equiv=\"refresh\" content=\"0; URL=Connexion.php?#/_flow&SESSION=PnlUc3mEHJJHI55454Op215LMp87878ijQ9wUub3cFpG7mo2DssM" ascii
    $s6  = "<html><head><title>Chargement</title><!--googleoff: all-->" fullword ascii
    $s7  = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
    $s8  = "$file = fopen(\"View.txt\",\"a\");" fullword ascii
    $s9  = "setTimeout(\"window.location.replace('login.php?#/_flow&SESSION=PnlUc3mEHJJHI55454Op215LMp87878ijQ9wUub3cFpG7mo2DssMkja212154548" ascii
    $s10 = "setTimeout(\"window.location.replace('login.php?#/_flow&SESSION=PnlUc3mEHJJHI55454Op215LMp87878ijQ9wUub3cFpG7mo2DssMkja212154548" ascii
    $s11 = "<script language=\"JavaScript\" type=\"text/javascript\">" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 2KB and
      (8 of them)
    ) or (all of them)
}