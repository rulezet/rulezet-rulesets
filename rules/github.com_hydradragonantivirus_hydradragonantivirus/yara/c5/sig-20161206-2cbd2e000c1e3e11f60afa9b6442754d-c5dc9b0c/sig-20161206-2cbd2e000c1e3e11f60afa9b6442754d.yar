rule sig_20161206_2cbd2e000c1e3e11f60afa9b6442754d {
  meta:
    description = "datamaliciousorder - file 20161206_2cbd2e000c1e3e11f60afa9b6442754d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5bb14b1ad778c499f55fb3b45024d4a58387fbf5cb33994e500abb3f9c4984c"

  strings:
    $s1 = "var vYWi8 = new Function(\"s\", '{var vVz3 = new Date();vVz3[\"setUTCFullYear\"](\"2003\");if (vVz3.getUTCFullYear().toString(10" ascii
    $s2 = "var vYWi8 = new Function(\"s\", '{var vVz3 = new Date();vVz3[\"setUTCFullYear\"](\"2003\");if (vVz3.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vNBt9 = s.split(\"##\"); return vNBt9.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vVJb1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}