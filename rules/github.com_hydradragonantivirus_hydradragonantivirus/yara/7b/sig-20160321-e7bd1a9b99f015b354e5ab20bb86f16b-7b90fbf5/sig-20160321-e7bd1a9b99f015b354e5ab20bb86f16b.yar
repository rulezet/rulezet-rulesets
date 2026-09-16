rule sig_20160321_e7bd1a9b99f015b354e5ab20bb86f16b {
  meta:
    description = "datamaliciousorder - file 20160321_e7bd1a9b99f015b354e5ab20bb86f16b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1da338caa2b8dd1313b8bd8feb8cec4c2e724bd747c84b93af8745ad7440c49f"

  strings:
    $s1 = "        return WScript[a](r);" fullword ascii
    $s2 = "var dregsLXX = function(r) {" fullword ascii
    $s3 = "    var s = String[\"fr\" + \"o\" + \"mCh\" + \"a\" + \"rCode\"];" fullword ascii
    $s4 = "        for (r = 0; r < a; r++) lookup[r] = code[r];" fullword ascii
    $s5 = "var cadaverousKOR = function() {" fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}