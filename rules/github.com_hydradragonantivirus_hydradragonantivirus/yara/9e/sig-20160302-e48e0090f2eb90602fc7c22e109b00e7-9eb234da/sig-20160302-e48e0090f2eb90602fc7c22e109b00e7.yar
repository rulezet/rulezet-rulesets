rule sig_20160302_e48e0090f2eb90602fc7c22e109b00e7 {
  meta:
    description = "datamaliciousorder - file 20160302_e48e0090f2eb90602fc7c22e109b00e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aafc4b104b503b2a1dd55ffc6056ed0a93dc4675b99eb16acd78fb76402cfd0b"

  strings:
    $s1 = "            return c((e >>> 10) + 55296) + c((1023 & e) + 56320);" fullword ascii
    $s2 = "var pertinaciousYNN = function() {" fullword ascii
    $s3 = "var estrangesp7 = function(r) {" fullword ascii
    $s4 = "    var a = String[\"fr\" + \"o\" + \"m\" + \"Ch\" + \"ar\" + \"Code\"];" fullword ascii
    $s5 = "        decode: B," fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}