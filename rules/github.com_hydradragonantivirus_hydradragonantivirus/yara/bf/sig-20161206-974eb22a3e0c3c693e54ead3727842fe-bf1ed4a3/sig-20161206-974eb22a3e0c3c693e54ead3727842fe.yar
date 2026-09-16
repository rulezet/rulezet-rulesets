rule sig_20161206_974eb22a3e0c3c693e54ead3727842fe {
  meta:
    description = "datamaliciousorder - file 20161206_974eb22a3e0c3c693e54ead3727842fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c5d06215d6e776107b430021099b94c912c7e830b6d7d0b52294710fff8bd40"

  strings:
    $s1 = "var vVj9 = new Function(\"s\", '{var vDt8 = new Date();vDt8[\"setUTCFullYear\"](\"2003\");if (vDt8.getUTCFullYear().toString(10)" ascii
    $s2 = "var vVj9 = new Function(\"s\", '{var vDt8 = new Date();vDt8[\"setUTCFullYear\"](\"2003\");if (vDt8.getUTCFullYear().toString(10)" ascii
    $s3 = "function vWSc7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vXo2 = s.split(\"##\"); return vXo2.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}