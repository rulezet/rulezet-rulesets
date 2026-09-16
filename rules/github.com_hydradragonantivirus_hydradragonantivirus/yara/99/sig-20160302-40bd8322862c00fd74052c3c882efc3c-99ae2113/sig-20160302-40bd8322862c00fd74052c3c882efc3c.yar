rule sig_20160302_40bd8322862c00fd74052c3c882efc3c {
  meta:
    description = "datamaliciousorder - file 20160302_40bd8322862c00fd74052c3c882efc3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7450e7ab3455d533a1613c6cef0cc85cf0056864671b1246bb368eb9982a71bf"

  strings:
    $s1  = "            return u((t >>> 10) + 55296) + u((1023 & t) + 56320);" fullword ascii
    $s2  = "            return a < 128 ? r : a < 2048 ? u(192 | a >>> 6) + u(128 | 63 & a) : u(224 | a >>> 12 & 15) + u(128 | a >>> 6 & 63) " ascii
    $s3  = "            return u(240 | a >>> 18 & 7) + u(128 | a >>> 12 & 63) + u(128 | a >>> 6 & 63) + u(128 | 63 & a);" fullword ascii
    $s4  = "            return a < 128 ? r : a < 2048 ? u(192 | a >>> 6) + u(128 | 63 & a) : u(224 | a >>> 12 & 15) + u(128 | a >>> 6 & 63) " ascii
    $s5  = "        return WScript[a](r);" fullword ascii
    $s6  = "var affectyBf = function() {" fullword ascii
    $s7  = "    var i = String[\"fro\" + \"m\" + \"C\" + \"h\" + \"arCode\"];" fullword ascii
    $s8  = "        VERSION: t," fullword ascii
    $s9  = "        decode: B," fullword ascii
    $s10 = "var cabalu97 = function(r) {" fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}