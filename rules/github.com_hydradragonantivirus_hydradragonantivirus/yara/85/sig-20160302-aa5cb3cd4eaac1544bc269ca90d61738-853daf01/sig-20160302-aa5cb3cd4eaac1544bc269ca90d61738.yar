rule sig_20160302_aa5cb3cd4eaac1544bc269ca90d61738 {
  meta:
    description = "datamaliciousorder - file 20160302_aa5cb3cd4eaac1544bc269ca90d61738.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55ec12b7d4029b0b7b5ffd343c2f6913db49ef2b4a2287db14705e10a41b86b4"

  strings:
    $s1 = "            return t < 128 ? r : t < 2048 ? u(192 | t >>> 6) + u(128 | 63 & t) : u(224 | t >>> 12 & 15) + u(128 | t >>> 6 & 63) " ascii
    $s2 = "            return u((n >>> 10) + 55296) + u((1023 & n) + 56320);" fullword ascii
    $s3 = "            return t < 128 ? r : t < 2048 ? u(192 | t >>> 6) + u(128 | 63 & t) : u(224 | t >>> 12 & 15) + u(128 | t >>> 6 & 63) " ascii
    $s4 = "            return u(240 | t >>> 18 & 7) + u(128 | t >>> 12 & 63) + u(128 | t >>> 6 & 63) + u(128 | 63 & t);" fullword ascii
    $s5 = "var contractGi5 = function() {" fullword ascii
    $s6 = "    var v = String[\"f\" + \"r\" + \"om\" + \"CharCode\"];" fullword ascii
    $s7 = "        VERSION: n," fullword ascii
    $s8 = "var cantoBEr = function(r) {" fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}