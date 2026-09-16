rule sig_20160301_44f68efd2a43f8383ce5e3da5ea77710 {
  meta:
    description = "datamaliciousorder - file 20160301_44f68efd2a43f8383ce5e3da5ea77710.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48c248bed4b7f6a9f6c24c7e75202b9b56bf4fb6fb268a34c605a9f6df0c6ccd"

  strings:
    $s1 = "while(legionCybernetics[(\"q\\u0075a\\u0072a\\u006e\\u0074\\u0069ne\", \"\\u0070\\u0072a\\u0063t\\u0069\\u0063al\", \"re\\u0061d" ascii
    $s2 = "styleManifesto[(\"\\u0073\\u0070o\\u0072t\", \"\\u006d\\u0065\\u0064ici\\u006e\\u0065\", function String.prototype.chiefIndustri" ascii
    $s3 = "while(legionCybernetics[(\"q\\u0075a\\u0072a\\u006e\\u0074\\u0069ne\", \"\\u0070\\u0072a\\u0063t\\u0069\\u0063al\", \"re\\u0061d" ascii
    $s4 = "meridianTender = (((6 | 33) ^ (20, 190, 23)), this);" fullword ascii
    $s5 = "} catch(forumAdministration) {};" fullword ascii

  condition:
    uint16(0) == 0x656d and
    all of them
}