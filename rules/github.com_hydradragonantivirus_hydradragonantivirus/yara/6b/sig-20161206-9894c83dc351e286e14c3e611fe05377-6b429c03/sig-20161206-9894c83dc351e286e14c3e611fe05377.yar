rule sig_20161206_9894c83dc351e286e14c3e611fe05377 {
  meta:
    description = "datamaliciousorder - file 20161206_9894c83dc351e286e14c3e611fe05377.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "332f4e24818e156fe25f0b26cf6ab6a0d27b8e874edf124d98c0c29c22ff2d80"

  strings:
    $s1 = "var vWl6 = new Function(\"s\", '{var vFDb3 = new Date();vFDb3[\"setUTCFullYear\"](\"2003\");if (vFDb3.getUTCFullYear().toString(" ascii
    $s2 = "var vWl6 = new Function(\"s\", '{var vFDb3 = new Date();vFDb3[\"setUTCFullYear\"](\"2003\");if (vFDb3.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vYz6 = s.split(\"##\"); return vYz6.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vHAn5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}