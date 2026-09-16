rule sig_20161206_ee6ded987a09b5dbf7456aa1fadc6add {
  meta:
    description = "datamaliciousorder - file 20161206_ee6ded987a09b5dbf7456aa1fadc6add.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc9fe89470ea9ce7f8fdb3065cd440a730de1594ec174643436d8a22c906328b"

  strings:
    $s1 = "var vPHm8 = new Function(\"s\", '{var vLd6 = new Date();vLd6[\"setUTCFullYear\"](\"2003\");if (vLd6.getUTCFullYear().toString(10" ascii
    $s2 = "var vPHm8 = new Function(\"s\", '{var vLd6 = new Date();vLd6[\"setUTCFullYear\"](\"2003\");if (vLd6.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vLp2 = s.split(\"##\"); return vLp2.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vZu80(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}