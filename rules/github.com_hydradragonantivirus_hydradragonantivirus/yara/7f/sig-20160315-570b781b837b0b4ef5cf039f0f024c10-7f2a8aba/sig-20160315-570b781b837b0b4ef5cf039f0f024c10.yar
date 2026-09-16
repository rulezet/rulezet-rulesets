rule sig_20160315_570b781b837b0b4ef5cf039f0f024c10 {
  meta:
    description = "datamaliciousorder - file 20160315_570b781b837b0b4ef5cf039f0f024c10.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58df4bd6394750280f73a94ed57644adf7b3461141da658dd68c9e0afb4c2681"

  strings:
    $s1 = "        return WScript[v](r);" fullword ascii
    $s2 = "var divulgelY2 = function(r) {" fullword ascii
    $s3 = "var munificentKTF = function() {" fullword ascii
    $s4 = "    var t = String[\"fr\" + \"omC\" + \"har\" + \"Code\"];" fullword ascii
    $s5 = "        for (r = 0; r < v; r++) lookup[r] = code[r];" fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}