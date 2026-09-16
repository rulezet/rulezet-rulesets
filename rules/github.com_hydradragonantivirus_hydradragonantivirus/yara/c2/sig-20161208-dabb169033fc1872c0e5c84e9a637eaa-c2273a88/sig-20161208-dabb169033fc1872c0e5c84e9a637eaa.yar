rule sig_20161208_dabb169033fc1872c0e5c84e9a637eaa {
  meta:
    description = "datamaliciousorder - file 20161208_dabb169033fc1872c0e5c84e9a637eaa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0c3abb0f12c8d8b870d638f840bac92874e6cdfdee2e9b540dcf1520ee0314b"

  strings:
    $s1 = "var vCOn9 = new Function(\"vMb1\", '{return vMb1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAu9 = new Function(\"vMb1" ascii
    $s2 = " new Date();vDKp1[\"setUTC\"+\"FullYear\"](\"2003\");if (vDKp1.getUTCFullYear().toString(10) == \"2003\") {var vXt5 = vMb1.split" ascii
    $s3 = "var vCOn9 = new Function(\"vMb1\", '{return vMb1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAu9 = new Function(\"vMb1" ascii
    $s4 = "; return vXt5.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}