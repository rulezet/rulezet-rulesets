rule sig_20161206_8d6d9692c0699ca8367afd630a847060 {
  meta:
    description = "datamaliciousorder - file 20161206_8d6d9692c0699ca8367afd630a847060.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48cdf11cdca245b83ed67e9a728101199497d7e4d7ebbad2d67125b1eae31466"

  strings:
    $s1 = "var vCDc6 = new Function(\"s\", '{var vEc5 = new Date();vEc5[\"setUTCFullYear\"](\"2003\");if (vEc5.getUTCFullYear().toString(10" ascii
    $s2 = "var vCDc6 = new Function(\"s\", '{var vEc5 = new Date();vEc5[\"setUTCFullYear\"](\"2003\");if (vEc5.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vEGb0 = s.split(\"##\"); return vEGb0.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vSz7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}