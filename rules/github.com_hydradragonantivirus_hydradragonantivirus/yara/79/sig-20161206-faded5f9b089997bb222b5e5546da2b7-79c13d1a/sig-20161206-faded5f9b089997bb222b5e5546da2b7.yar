rule sig_20161206_faded5f9b089997bb222b5e5546da2b7 {
  meta:
    description = "datamaliciousorder - file 20161206_faded5f9b089997bb222b5e5546da2b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bcd38773d658cb38108dc98db4b13f5658318b17653999a01f9b4b1bc35cf32"

  strings:
    $s1 = "var vBs8 = new Function(\"s\", '{var vLJn4 = new Date();vLJn4[\"setUTCFullYear\"](\"2003\");if (vLJn4.getUTCFullYear().toString(" ascii
    $s2 = "var vBs8 = new Function(\"s\", '{var vLJn4 = new Date();vLJn4[\"setUTCFullYear\"](\"2003\");if (vLJn4.getUTCFullYear().toString(" ascii
    $s3 = "function vBUk3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vRAu2 = s.split(\"##\"); return vRAu2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}