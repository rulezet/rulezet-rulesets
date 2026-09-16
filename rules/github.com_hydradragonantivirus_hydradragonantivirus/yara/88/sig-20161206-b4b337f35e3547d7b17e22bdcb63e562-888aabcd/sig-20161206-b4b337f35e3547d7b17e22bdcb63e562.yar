rule sig_20161206_b4b337f35e3547d7b17e22bdcb63e562 {
  meta:
    description = "datamaliciousorder - file 20161206_b4b337f35e3547d7b17e22bdcb63e562.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9b5c6e47f5a85613b0d05825a34da64a9b78d4701f3f3f5f9bc9705878292f8"

  strings:
    $s1 = "var vBo6 = new Function(\"s\", '{var vTCg0 = new Date();vTCg0[\"setUTCFullYear\"](\"2003\");if (vTCg0.getUTCFullYear().toString(" ascii
    $s2 = "var vBo6 = new Function(\"s\", '{var vTCg0 = new Date();vTCg0[\"setUTCFullYear\"](\"2003\");if (vTCg0.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vVOx0 = s.split(\"##\"); return vVOx0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vBJz0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}