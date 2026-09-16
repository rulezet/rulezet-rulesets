rule sig_20160302_0f2099befb269c1982b9b09411c6bd4b {
  meta:
    description = "datamaliciousorder - file 20160302_0f2099befb269c1982b9b09411c6bd4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b84062c16de9634b8239a6eecbd5e75123bc3c818a8689c54f8eb6e09805900"

  strings:
    $s1  = "            return e < 128 ? r : e < 2048 ? u(192 | e >>> 6) + u(128 | 63 & e) : u(224 | e >>> 12 & 15) + u(128 | e >>> 6 & 63) " ascii
    $s2  = "            return e < 128 ? r : e < 2048 ? u(192 | e >>> 6) + u(128 | 63 & e) : u(224 | e >>> 12 & 15) + u(128 | e >>> 6 & 63) " ascii
    $s3  = "            return u((t >>> 10) + 55296) + u((1023 & t) + 56320);" fullword ascii
    $s4  = "            return u(240 | e >>> 18 & 7) + u(128 | e >>> 12 & 63) + u(128 | e >>> 6 & 63) + u(128 | 63 & e);" fullword ascii
    $s5  = "        return WScript[e](r);" fullword ascii
    $s6  = "var refectoryGsU = function() {" fullword ascii
    $s7  = "var forsakejdN = function(r) {" fullword ascii
    $s8  = "    var f = String[\"f\" + \"ro\" + \"mC\" + \"h\" + \"ar\" + \"Code\"];" fullword ascii
    $s9  = "        VERSION: t," fullword ascii
    $s10 = "        decode: b," fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}