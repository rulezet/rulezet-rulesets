rule sig_20160302_25ae43f6dd53efcc3bbb83ef6f0ba3dc {
  meta:
    description = "datamaliciousorder - file 20160302_25ae43f6dd53efcc3bbb83ef6f0ba3dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "965f6d2649d00a0ced1240e7f740b35f2ebe89b68bb45c296f2a728b86d33ad8"

  strings:
    $s1 = "            return c((e >>> 10) + 55296) + c((1023 & e) + 56320);" fullword ascii
    $s2 = "var trenchantdV9 = function() {" fullword ascii
    $s3 = "var enamorzG7 = function(r) {" fullword ascii
    $s4 = "    var d = String[\"fr\" + \"o\" + \"mC\" + \"har\" + \"Code\"];" fullword ascii
    $s5 = "        decode: b," fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}