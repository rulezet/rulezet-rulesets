rule sig_20161206_08171395d21a59fbee7c491ff8ebc9a4 {
  meta:
    description = "datamaliciousorder - file 20161206_08171395d21a59fbee7c491ff8ebc9a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "348066abcd674acf6efedef65b341543129d33aa89663d48e74f1c0961433ee5"

  strings:
    $s1 = "var vOFp6 = new Function(\"s\", '{var vEQj9 = new Date();vEQj9[\"setUTCFullYear\"](\"2003\");if (vEQj9.getUTCFullYear().toString" ascii
    $s2 = "var vOFp6 = new Function(\"s\", '{var vEQj9 = new Date();vEQj9[\"setUTCFullYear\"](\"2003\");if (vEQj9.getUTCFullYear().toString" ascii
    $s3 = "= \"2003\") {var vDy8 = s.split(\"##\"); return vDy8.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vEQz8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}