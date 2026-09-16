rule Congratulations {
  meta:
    description = "case127 - file Congratulations.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "37630f4a947fe6f850756502200f36fbcb2fb04c4e3484fb290698b85a3ffcd4"

  strings:
    $s1 = "<meta http-equiv=\"refresh\" content=\"5; url=https://www.paypal.com/\">" fullword ascii
    $s2 = "9ff;\" href=\"https://www.paypal.com/\" >cliquez ici</a> </p>" fullword ascii
    $s3 = "<p style=\"font-size:12px;\">Si cette page appara&icirc;t pendant plus de 10 secondes, <a style=\"text-decoration: none;color: #" ascii
    $s4 = "<h1>F&eacute;licitations, Confirmation Termin&eacute; !</h1>" fullword ascii
    $s5 = "<center><img src=\"images/pasy.gif\" /></center><br />" fullword ascii
    $s6 = "<link rel=\"stylesheet\" href=\"css/styl.css\" />" fullword ascii
    $s7 = "<link rel=\"stylesheet\" href=\"css/normalize.css\" />" fullword ascii
    $s8 = "<link rel=\"icon\" href=\"images/pp_favicon_x.ico\" />" fullword ascii
    $s9 = "/ =     =    =   -  ( =  =    = )  -   =  =       = \\" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and
      filesize < 8KB and
      (all of them)
    ) or (all of them)
}