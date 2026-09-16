rule sig_20161206_ce81c5b2d02bf0da8a4a32af9d2f1ef7 {
  meta:
    description = "datamaliciousorder - file 20161206_ce81c5b2d02bf0da8a4a32af9d2f1ef7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39d609f90657066cea841093d69e2d8e240880376567ca764510d7cbd0750d86"

  strings:
    $s1 = "var vBd0 = new Function(\"s\", '{var vXAs5 = new Date();vXAs5[\"setUTCFullYear\"](\"2003\");if (vXAs5.getUTCFullYear().toString(" ascii
    $s2 = "var vBd0 = new Function(\"s\", '{var vXAs5 = new Date();vXAs5[\"setUTCFullYear\"](\"2003\");if (vXAs5.getUTCFullYear().toString(" ascii
    $s3 = " \"2003\") {var vXd2 = s.split(\"##\"); return vXd2.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vGe4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}