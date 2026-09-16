rule sig_20160823_28f3d5c3465f912de027c8220eec04ed {
  meta:
    description = "datamaliciousorder - file 20160823_28f3d5c3465f912de027c8220eec04ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7136fedcb84f4b79cddce26048c0e69068eba4404fcbd11fd1a5c0e3ea8803c1"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}