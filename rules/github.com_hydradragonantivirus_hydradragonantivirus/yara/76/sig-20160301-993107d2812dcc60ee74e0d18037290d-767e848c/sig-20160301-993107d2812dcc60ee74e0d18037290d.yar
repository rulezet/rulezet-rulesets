rule sig_20160301_993107d2812dcc60ee74e0d18037290d {
  meta:
    description = "datamaliciousorder - file 20160301_993107d2812dcc60ee74e0d18037290d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1bf7b852a492a28d60afab74ba284820a4ac9695aada098036e17f99724a6c7"

  strings:
    $s1 = "illustrateObject = proportionalProfession[(\"\\u006fr\\u0069\" + \"gin\", \"\\u0072e\\u0076ue\", \"di\" + \"r\\u0065\" + \"ct\\u" ascii
    $s2 = "while (actorReal[(\"r\\u0065\\u0061\\u0064y\" + \"st\" + \"a\\u0074\\u0065\")] < ((([!+[] + !+[]])) ^ (0 ^ 6))) {" fullword ascii
    $s3 = "+ \"\\u0072\\u0069nc\\u0065\") + (\"\\u0073pi\" + \"\\u0072\\u0061\\u006c\", \"pe\\u0064\\u0061\\u006c\", \"\\u0064\\u0065\\u006" ascii
    $s4 = "} catch (startEvolution) {};" fullword ascii
    $s5 = "mechanicAuction = ((([+!+[]])), this);" fullword ascii

  condition:
    uint16(0) == 0x656d and
    all of them
}