rule sig_20161206_df04ce5d19cf082923331e7228d37be3 {
  meta:
    description = "datamaliciousorder - file 20161206_df04ce5d19cf082923331e7228d37be3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "026f30a18b784447f6595973f9c74ffb97217c9eb01f3d777b55905feae3a646"

  strings:
    $s1 = "var vUXe6 = new Function(\"s\", '{var vMe7 = new Date();vMe7[\"setUTCFullYear\"](\"2003\");if (vMe7.getUTCFullYear().toString(10" ascii
    $s2 = "var vUXe6 = new Function(\"s\", '{var vMe7 = new Date();vMe7[\"setUTCFullYear\"](\"2003\");if (vMe7.getUTCFullYear().toString(10" ascii
    $s3 = "function vTp3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vWj1 = s.split(\"##\"); return vWj1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}