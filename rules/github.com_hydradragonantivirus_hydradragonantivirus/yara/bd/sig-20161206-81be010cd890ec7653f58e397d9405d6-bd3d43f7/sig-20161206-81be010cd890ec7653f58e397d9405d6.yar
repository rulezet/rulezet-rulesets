rule sig_20161206_81be010cd890ec7653f58e397d9405d6 {
  meta:
    description = "datamaliciousorder - file 20161206_81be010cd890ec7653f58e397d9405d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94319a1a3a8c9d2907f357d71ff25848ae77a344cc01b2ad88b2fdea3a9d44b1"

  strings:
    $s1 = "var vJKg9 = new Function(\"s\", '{var vPEx8 = new Date();vPEx8[\"setUTCFullYear\"](\"2003\");if (vPEx8.getUTCFullYear().toString" ascii
    $s2 = "var vJKg9 = new Function(\"s\", '{var vPEx8 = new Date();vPEx8[\"setUTCFullYear\"](\"2003\");if (vPEx8.getUTCFullYear().toString" ascii
    $s3 = "function vIy2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vBLu7 = s.split(\"##\"); return vBLu7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}