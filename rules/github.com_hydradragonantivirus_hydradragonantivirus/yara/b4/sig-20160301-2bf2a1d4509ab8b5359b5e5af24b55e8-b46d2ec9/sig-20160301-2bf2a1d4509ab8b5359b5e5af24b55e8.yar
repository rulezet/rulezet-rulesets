rule sig_20160301_2bf2a1d4509ab8b5359b5e5af24b55e8 {
  meta:
    description = "datamaliciousorder - file 20160301_2bf2a1d4509ab8b5359b5e5af24b55e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6303b62a369059b09b12fee92b4a6f25d6953b61f05a7cb6c9918da8dcb8c8a3"

  strings:
    $s1 = "while (originalOrigin[(\"re\" + \"\\u0061\\u0064y\\u0073\" + \"\\u0074at\\u0065\")] < ((11 | 28) - (9 + 18))) {" fullword ascii
    $s2 = "proportionalSanction = (\"\\u0070\\u0072o\\u0066\" + \"e\" + \"s\\u0073\\u0069\" + \"on\", function String.prototype.detailDicti" ascii
    $s3 = "barrelResistor = (((204, 1) & (([+!+[]]))), this);" fullword ascii
    $s4 = "} catch (barrelFacade) {};" fullword ascii

  condition:
    uint16(0) == 0x6162 and
    all of them
}