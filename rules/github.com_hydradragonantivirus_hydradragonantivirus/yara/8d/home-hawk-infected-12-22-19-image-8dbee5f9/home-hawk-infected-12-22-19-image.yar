rule _home_hawk_infected_12_22_19_image {
  meta:
    description = "12-22-19 - file image.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-12-22"
    hash1       = "ed4e15e61e44506cd384524c8548522f30c9ff9635bb37fb4dcb8c73764ede85"

  strings:
    $s1  = "/*4fdde239a36aa4d71f1e9570d9228bdc5f49b6de01950679e52f8b26a6fe32b4 */?><?php $ZpvfC9758 = \"/mhol(x8v6fzu.5iryn*bq49gesd3_20tkpw" ascii
    $s2  = "k/iOZ2gEZbaI3gTK4giWlqT472T9/tHO9ZsqlERni1p3Zv5JDAO/b7MzxQTQWCSOp8BTtOp2/sUBFDZK8m0VVg51M1shDLlRgFBd5TtnfqG2+evzH24w2UbBCg2V49Lk" ascii
    $s3  = "iozkP/lT90J+W4zX3XKZtb0KOG7bnDSasH/eYE7a2BH4yNsRON/H5r6odR+w0Q09wP+hvGljuZziIjupk6rSn/akzsMXtry8nhrAuoGle2N3NaVrtttbfWEDL8gSrbNK" ascii
    $s4  = "3HnFFMmK7HfdeuNGsOdRrbG11loggk3rDUa7GdmS7GE+s3Ftg4/4KGW+NEe7VME3OtwmcTxR0gdc2VTrZQAoTYMKQwwnvkbmHw2CPYTK5T2OTur7CmRX5wU0MnoPJqQx" ascii
    $s5  = "u6Fk+wXEDA6qKA9G15gBBRNwxnTm3iRCokin6jO23OrHt0Ej6YeYnpzLCH5hEe/ct+AgFYY/sSjVimZAMDUhraxUxvohG20wpm3Rv4E9nAlqzh3y7m6SZ/mvB3QpDIyw" ascii
    $s6  = "RRCHPrhCzGhYUuNzwkaNbyJ8m+YelibA7E1KyRPZLJIjAKaxBIpQlNlGChL7dJFya1rM9J2heLjBEtDLl4TuWL0KDd7ieMy8jMkOykr/I6Ro18GBPnRpKXGTQJKPidL4" ascii
    $s7  = "4fdde239a36aa4d71f1e9570d9228bdc5f49b6de01950679e52f8b26a6fe32b4" ascii
    $s8  = "lEmJZTNKt6LGiSc4TPWfAxotM5VpLgTVXq6oyzDIOhUmKYKcEbinWdW0hOsUJEQoGlwj9qomgEVqsrzLBhqUOp8BdhtYKmBR0cWpI6BMWVpnY0gg9EuTDSzGohZ35NWn" ascii
    $s9  = "935/0NXEzzuvixhbmeUg9s0AzF9RfkVIQPY9dvW0mPYQp82Zr4UEZaoiXRpVI1QDRuNOsEJ6EgzJ0s+6g7iewAFrBWp+vZk8v2uSrVUB9urVFFW7wyWroQaNlgr7jQ4X" ascii
    $s10 = "lBGDLXttbsmHtJ3ccYXHIMbp2d7q8+wtVZMeaD95dHB49Wj+NfZ/irN3308GHCO/xprBVTxgMa6ti9UTmpzg6hPyNnLE97pTSai2z5xEi43ZZp1ahIDUQ5q5ZV4LValP" ascii
    $s11 = "SlEIHTe4PWQ+XSRAnrQH1wRQFOXEi8Uk2pyqmcEmq0LaKOmiABbhh8pySfz3IgQrC/qhpksQlLRdb+QQEPGAldeQqcOmVSOGEkDdYVY6/BkGOAKOCFDOpL6khY7iFLdL" ascii
    $s12 = "<?php /*2f2512d8c52ceb5320bf4012b2bbeb10b41209ab*/" fullword ascii
    $s13 = "if ($_SERVER[\"QUERY_STRING\"]) { exit($_SERVER[\"QUERY_STRING\"]); }" fullword ascii
    $s14 = "7uzf8H'\".$zwZxFb7128));$c255($Q8500,array('','}'.$Tx4853.'//'));" fullword ascii
    $s15 = "2f2512d8c52ceb5320bf4012b2bbeb10b41209ab" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 80KB and
      (8 of them)
    ) or (all of them)
}