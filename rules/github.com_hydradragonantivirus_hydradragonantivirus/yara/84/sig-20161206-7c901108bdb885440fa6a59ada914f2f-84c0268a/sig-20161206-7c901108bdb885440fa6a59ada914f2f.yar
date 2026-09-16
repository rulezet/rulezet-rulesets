rule sig_20161206_7c901108bdb885440fa6a59ada914f2f {
  meta:
    description = "datamaliciousorder - file 20161206_7c901108bdb885440fa6a59ada914f2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28e0863fc4feedd93d78132b4220b731a5b707ff59f5ef460ed89787f3f22e81"

  strings:
    $s1 = "var vXf5 = new Function(\"s\", '{var vSGy1 = new Date();vSGy1[\"setUTCFullYear\"](\"2003\");if (vSGy1.getUTCFullYear().toString(" ascii
    $s2 = "var vXf5 = new Function(\"s\", '{var vSGy1 = new Date();vSGy1[\"setUTCFullYear\"](\"2003\");if (vSGy1.getUTCFullYear().toString(" ascii
    $s3 = "function vRRd0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vSn8 = s.split(\"##\"); return vSn8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}