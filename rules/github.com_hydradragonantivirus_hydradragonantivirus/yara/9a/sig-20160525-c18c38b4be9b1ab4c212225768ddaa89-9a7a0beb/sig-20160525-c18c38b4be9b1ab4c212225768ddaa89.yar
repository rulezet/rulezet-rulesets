rule sig_20160525_c18c38b4be9b1ab4c212225768ddaa89 {
  meta:
    description = "datamaliciousorder - file 20160525_c18c38b4be9b1ab4c212225768ddaa89.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c02af96e44faf8e2d6e8b8f77016d1a578d34edc118dbbbd49799aac23a52af"

  strings:
    $s1 = "er{)rerednerl(cthl noitcnuf;};tsilslianbmuhtol nruter{)tsilslianbmuhtol(ssorcal noitcnuf\\n;\"07x\\\\o\" = gsmm rav\\n;\"e6x" ascii
    $s2 = "ppelb rav\\n;\"p47x\\\\\" = ecapsetihwxelfb rav\\n;\"ahf2x\\\\f2x\\\\:\" = modnarb rav\\n;\"ge6x\\\\\" = sdnetb rav\\n;)1(]\"tAr" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}