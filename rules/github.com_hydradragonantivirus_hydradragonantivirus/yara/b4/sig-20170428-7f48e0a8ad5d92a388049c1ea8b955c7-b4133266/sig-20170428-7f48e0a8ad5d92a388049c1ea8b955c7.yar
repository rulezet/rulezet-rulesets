rule sig_20170428_7f48e0a8ad5d92a388049c1ea8b955c7 {
  meta:
    description = "datamaliciousorder - file 20170428_7f48e0a8ad5d92a388049c1ea8b955c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "712e3d43a94f73967466cdb547219be90abf7495d736c8afdcf02d536d021c55"

  strings:
    $s1 = "function bGtwVYdvglakSTAJe(xkKErTzNoAGwFvWje, GjlfuoKywePJzWBX, GirwUlvHMgOSnDsZaCc) { " fullword ascii
    $s2 = "return xkKErTzNoAGwFvWje.split(GjlfuoKywePJzWBX).join(GirwUlvHMgOSnDsZaCc); }" fullword ascii
    $s3 = "//if (vVNXbfeiTclAydzDw() == false) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}