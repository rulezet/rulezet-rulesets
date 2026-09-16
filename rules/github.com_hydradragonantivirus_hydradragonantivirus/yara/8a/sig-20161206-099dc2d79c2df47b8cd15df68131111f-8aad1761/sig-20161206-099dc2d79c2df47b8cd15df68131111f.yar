rule sig_20161206_099dc2d79c2df47b8cd15df68131111f {
  meta:
    description = "datamaliciousorder - file 20161206_099dc2d79c2df47b8cd15df68131111f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "842443eb9d1ba17401f10945c724c03326a2954407063b5191094e8b5f9a58d8"

  strings:
    $s1 = "var vRBq2 = new Function(\"s\", '{var vHz1 = new Date();vHz1[\"setUTCFullYear\"](\"2003\");if (vHz1.getUTCFullYear().toString(10" ascii
    $s2 = "var vRBq2 = new Function(\"s\", '{var vHz1 = new Date();vHz1[\"setUTCFullYear\"](\"2003\");if (vHz1.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vMJj9 = s.split(\"##\"); return vMJj9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vVHv1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}