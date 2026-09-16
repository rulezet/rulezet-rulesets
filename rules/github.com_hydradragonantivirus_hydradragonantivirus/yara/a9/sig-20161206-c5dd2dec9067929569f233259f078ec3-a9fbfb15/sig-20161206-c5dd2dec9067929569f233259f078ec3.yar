rule sig_20161206_c5dd2dec9067929569f233259f078ec3 {
  meta:
    description = "datamaliciousorder - file 20161206_c5dd2dec9067929569f233259f078ec3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5672ed5dc286f2b0463d85fc157d467e418b3965447f8970d69478e632e4267"

  strings:
    $s1 = "var vIl1 = new Function(\"s\", '{var vZMa1 = new Date();vZMa1[\"setUTCFullYear\"](\"2003\");if (vZMa1.getUTCFullYear().toString(" ascii
    $s2 = "var vIl1 = new Function(\"s\", '{var vZMa1 = new Date();vZMa1[\"setUTCFullYear\"](\"2003\");if (vZMa1.getUTCFullYear().toString(" ascii
    $s3 = "function vQQq2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vHv3 = s.split(\"##\"); return vHv3.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}