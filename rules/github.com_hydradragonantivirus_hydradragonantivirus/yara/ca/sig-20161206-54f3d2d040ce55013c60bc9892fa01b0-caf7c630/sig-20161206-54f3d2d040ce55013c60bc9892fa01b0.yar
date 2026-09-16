rule sig_20161206_54f3d2d040ce55013c60bc9892fa01b0 {
  meta:
    description = "datamaliciousorder - file 20161206_54f3d2d040ce55013c60bc9892fa01b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3594ef902b2a1296f134ae8871427c2b5b9adb841f33734b640834cb2676832c"

  strings:
    $s1 = "var vLm0 = new Function(\"s\", '{var vBz2 = new Date();vBz2[\"setUTCFullYear\"](\"2003\");if (vBz2.getUTCFullYear().toString(10)" ascii
    $s2 = "var vLm0 = new Function(\"s\", '{var vBz2 = new Date();vBz2[\"setUTCFullYear\"](\"2003\");if (vBz2.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vJb4 = s.split(\"##\"); return vJb4.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vGCa2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}