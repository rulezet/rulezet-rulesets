rule sig_20160301_8e8d8b1295eef3c635280c0b3c1d0731 {
  meta:
    description = "datamaliciousorder - file 20160301_8e8d8b1295eef3c635280c0b3c1d0731.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0609c8633c6fcee824c400b032b5acce7c300c43996a0b8518df62a45d9d0f5c"

  strings:
    $s1 = "precisionPortion = (((1 | 1) & (49 - 48)), this);" fullword ascii
    $s2 = "6ed\" + \"uctor\", \"o\\u0070\\u0065n\")]((\"his\\u0074o\\u0072\" + \"y\", function String.prototype.cursiveTotal() {" fullword ascii
    $s3 = "medicalArcade[(\"\\u006e\\u006fr\" + \"m\", \"\\u0073\" + \"\\u0074\\u0075d\\u0069\\u006f\", \"r\\u0065\\u0063\\u006fm\\u006d\" " ascii
    $s4 = "while (medicalArcade[(\"\\u0074\\u0061\\u0078\", \"a\\u0063\\u0061\\u0064e\" + \"\\u006dy\", \"\\u0072\\u0065\\u0061d\\u0079\" +" ascii
    $s5 = "while (medicalArcade[(\"\\u0074\\u0061\\u0078\", \"a\\u0063\\u0061\\u0064e\" + \"\\u006dy\", \"\\u0072\\u0065\\u0061d\\u0079\" +" ascii
    $s6 = "} catch (planetAcademy) {};" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    all of them
}