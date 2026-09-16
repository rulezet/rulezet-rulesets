rule sig_20160302_acd5fe86fa6c909b6783e118dc927c1b {
  meta:
    description = "datamaliciousorder - file 20160302_acd5fe86fa6c909b6783e118dc927c1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8656dc752f0e15665cb467873b2949c1002d5680eaf77d7b66b8e377e996abc2"

  strings:
    $s1  = "            return e < 128 ? r : e < 2048 ? u(192 | e >>> 6) + u(128 | 63 & e) : u(224 | e >>> 12 & 15) + u(128 | e >>> 6 & 63) " ascii
    $s2  = "            return e < 128 ? r : e < 2048 ? u(192 | e >>> 6) + u(128 | 63 & e) : u(224 | e >>> 12 & 15) + u(128 | e >>> 6 & 63) " ascii
    $s3  = "            return u((t >>> 10) + 55296) + u((1023 & t) + 56320);" fullword ascii
    $s4  = "            return u(240 | e >>> 18 & 7) + u(128 | e >>> 12 & 63) + u(128 | e >>> 6 & 63) + u(128 | 63 & e);" fullword ascii
    $s5  = "        return WScript[e](r);" fullword ascii
    $s6  = "var heedE3I = function(r) {" fullword ascii
    $s7  = "var reconditeBnO = function() {" fullword ascii
    $s8  = "    var u = String[\"fr\" + \"omC\" + \"h\" + \"arCode\"];" fullword ascii
    $s9  = "        VERSION: t," fullword ascii
    $s10 = "        decode: S," fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}