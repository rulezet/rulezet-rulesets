rule sig_20161206_a108ef383ae0de98c214b40035b45910 {
  meta:
    description = "datamaliciousorder - file 20161206_a108ef383ae0de98c214b40035b45910.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46459758780c9e80ce3396bed0319a58b153039ac29f48a23b8f807835288d6c"

  strings:
    $s1 = "var vNu2 = new Function(\"s\", '{var vRq3 = new Date();vRq3[\"setUTCFullYear\"](\"2003\");if (vRq3.getUTCFullYear().toString(10)" ascii
    $s2 = "var vNu2 = new Function(\"s\", '{var vRq3 = new Date();vRq3[\"setUTCFullYear\"](\"2003\");if (vRq3.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vWPv9 = s.split(\"##\"); return vWPv9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vFXa8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}