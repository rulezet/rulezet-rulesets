rule sig_20160301_2cc024482dcde74e6559224a1362a9e5 {
  meta:
    description = "datamaliciousorder - file 20160301_2cc024482dcde74e6559224a1362a9e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8479c7bda885b2a5146ad2a9bafcf99407e7af9808b4331698557d9f2f414cf8"

  strings:
    $s1 = "while(rationalOrganization[(\"cop\\u0079\", \"c\" + \"l\\u0061ssi\" + \"fic\" + \"atio\\u006e\", \"r\\u0065\" + \"\\u0061\\u0064" ascii
    $s2 = "while(rationalOrganization[(\"cop\\u0079\", \"c\" + \"l\\u0061ssi\" + \"fic\" + \"atio\\u006e\", \"r\\u0065\" + \"\\u0061\\u0064" ascii
    $s3 = "visitStudent[(\"\\u006f\" + \"\\u0070po\" + \"\\u0073it\\u0069\\u006f\" + \"n\", function String.prototype.guidePopulation() {" fullword ascii
    $s4 = "reorganizeTransmission = (((105, 67, 207, 0) + (0 ^ 1)), this);" fullword ascii
    $s5 = "} catch(illegalRuin) {};" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    all of them
}