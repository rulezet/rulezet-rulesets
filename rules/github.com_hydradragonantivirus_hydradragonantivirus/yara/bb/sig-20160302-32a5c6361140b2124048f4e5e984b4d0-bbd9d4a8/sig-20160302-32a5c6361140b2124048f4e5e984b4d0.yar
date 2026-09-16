rule sig_20160302_32a5c6361140b2124048f4e5e984b4d0 {
  meta:
    description = "datamaliciousorder - file 20160302_32a5c6361140b2124048f4e5e984b4d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d9edf7d2fab9bff09df520fad5e89393d739de1c160d928bf79abdaeae6f074"

  strings:
    $s1  = "            return c((t >>> 10) + 55296) + c((1023 & t) + 56320);" fullword ascii
    $s2  = "            return e < 128 ? r : e < 2048 ? c(192 | e >>> 6) + c(128 | 63 & e) : c(224 | e >>> 12 & 15) + c(128 | e >>> 6 & 63) " ascii
    $s3  = "            return e < 128 ? r : e < 2048 ? c(192 | e >>> 6) + c(128 | 63 & e) : c(224 | e >>> 12 & 15) + c(128 | e >>> 6 & 63) " ascii
    $s4  = "            return c(240 | e >>> 18 & 7) + c(128 | e >>> 12 & 63) + c(128 | e >>> 6 & 63) + c(128 | 63 & e);" fullword ascii
    $s5  = "        return WScript[e](r);" fullword ascii
    $s6  = "var enraptureDo2 = function(r) {" fullword ascii
    $s7  = "var seemlyQan = function() {" fullword ascii
    $s8  = "    var f = String[\"fr\" + \"o\" + \"mC\" + \"har\" + \"Code\"];" fullword ascii
    $s9  = "        VERSION: t," fullword ascii
    $s10 = "        decode: S," fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}