rule sig_20161206_f2d1ba6628b34a9b92a0ed9288247aeb {
  meta:
    description = "datamaliciousorder - file 20161206_f2d1ba6628b34a9b92a0ed9288247aeb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "368627c3e8fb94a4cef85ac3e39e9009f8dcb474185d9219118812fd43ada094"

  strings:
    $s1 = "var vRy0 = new Function(\"s\", '{var vBm0 = new Date();vBm0[\"setUTCFullYear\"](\"2003\");if (vBm0.getUTCFullYear().toString(10)" ascii
    $s2 = "var vRy0 = new Function(\"s\", '{var vBm0 = new Date();vBm0[\"setUTCFullYear\"](\"2003\");if (vBm0.getUTCFullYear().toString(10)" ascii
    $s3 = "function vUw0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vWr5 = s.split(\"##\"); return vWr5.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}