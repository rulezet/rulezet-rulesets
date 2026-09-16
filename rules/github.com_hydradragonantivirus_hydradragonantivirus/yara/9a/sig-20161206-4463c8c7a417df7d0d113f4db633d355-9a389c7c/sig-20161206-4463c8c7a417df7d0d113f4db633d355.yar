rule sig_20161206_4463c8c7a417df7d0d113f4db633d355 {
  meta:
    description = "datamaliciousorder - file 20161206_4463c8c7a417df7d0d113f4db633d355.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1397bdc3280b0308b72110b7750e48673b90cedec6898013ad7aebfc90810c9a"

  strings:
    $s1 = "var vCj2 = new Function(\"s\", '{var vOy0 = new Date();vOy0[\"setUTCFullYear\"](\"2003\");if (vOy0.getUTCFullYear().toString(10)" ascii
    $s2 = "var vCj2 = new Function(\"s\", '{var vOy0 = new Date();vOy0[\"setUTCFullYear\"](\"2003\");if (vOy0.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vXf4 = s.split(\"##\"); return vXf4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vMc0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}