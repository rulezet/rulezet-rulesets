rule sig_20161206_0d7e9a1435b249bff5563eacd3c535d4 {
  meta:
    description = "datamaliciousorder - file 20161206_0d7e9a1435b249bff5563eacd3c535d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e957c975de96f291c2693f4bd8af2ec9a3ae10f9d3eb9eb0b9994985e44336e"

  strings:
    $s1 = "var vSIm1 = new Function(\"s\", '{var vRf2 = new Date();vRf2[\"setUTCFullYear\"](\"2003\");if (vRf2.getUTCFullYear().toString(10" ascii
    $s2 = "var vSIm1 = new Function(\"s\", '{var vRf2 = new Date();vRf2[\"setUTCFullYear\"](\"2003\");if (vRf2.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vCSz6 = s.split(\"##\"); return vCSz6.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vGUp4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}