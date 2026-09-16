rule sig_20161206_bec88d718db3813fcd998f656b31b894 {
  meta:
    description = "datamaliciousorder - file 20161206_bec88d718db3813fcd998f656b31b894.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89ca96c14bbf4340defcdef272b687abc959764ee34cf073d49a81384b54e04d"

  strings:
    $s1 = "var vBd6 = new Function(\"s\", '{var vQPc1 = new Date();vQPc1[\"setUTCFullYear\"](\"2003\");if (vQPc1.getUTCFullYear().toString(" ascii
    $s2 = "var vBd6 = new Function(\"s\", '{var vQPc1 = new Date();vQPc1[\"setUTCFullYear\"](\"2003\");if (vQPc1.getUTCFullYear().toString(" ascii
    $s3 = "function vXp4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = " \"2003\") {var vCw2 = s.split(\"##\"); return vCw2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}