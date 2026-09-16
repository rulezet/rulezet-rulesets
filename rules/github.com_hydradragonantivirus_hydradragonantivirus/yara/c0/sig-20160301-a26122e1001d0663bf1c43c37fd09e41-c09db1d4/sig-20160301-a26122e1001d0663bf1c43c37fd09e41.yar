rule sig_20160301_a26122e1001d0663bf1c43c37fd09e41 {
  meta:
    description = "datamaliciousorder - file 20160301_a26122e1001d0663bf1c43c37fd09e41.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b8ee76567f96ba26ec5c720105a9b909d4d0fe5dff557cc22d0bbfc5415042e"

  strings:
    $s1 = "while(examineMotif[(\"s\" + \"\\u0075\" + \"\\u0066\\u0066\\u0069\\u0078\", \"\\u0074\\u0065x\\u0074\", \"s\\u0070\" + \"\\u006f" ascii
    $s2 = "while(examineMotif[(\"s\" + \"\\u0075\" + \"\\u0066\\u0066\\u0069\\u0078\", \"\\u0074\\u0065x\\u0074\", \"s\\u0070\" + \"\\u006f" ascii
    $s3 = "examineMotif[(\"\\u0061\\u0078\\u0069o\" + \"m\", \"o\\u0070\\u0065\\u006e\")]((\"\\u0062\\u0061\" + \"\\u0072\\u0062\\u0061\" +" ascii
    $s4 = "sumGrammar = ((1 & 1), this);" fullword ascii
    $s5 = "} catch(statuetteCompilation) {};" fullword ascii

  condition:
    uint16(0) == 0x7573 and
    all of them
}