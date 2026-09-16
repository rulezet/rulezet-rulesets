rule sig_20161208_7da04be10d0d87268aeb46bc6e8e505d {
  meta:
    description = "datamaliciousorder - file 20161208_7da04be10d0d87268aeb46bc6e8e505d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3509388337d69bdb9c39be611ef3f9994d13c2074785c40645700eb26727c838"

  strings:
    $s1 = "var vDt0 = new Function(\"vIp7\", '{return vIp7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNk2 = new Function(\"vIp7\"" ascii
    $s2 = "ew Date();vSj2[\"setUTC\"+\"FullYear\"](\"2003\");if (vSj2.getUTCFullYear().toString(10) == \"2003\") {var vQm8 = vIp7.split(\"#" ascii
    $s3 = "turn vQm8.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vDt0 = new Function(\"vIp7\", '{return vIp7[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vNk2 = new Function(\"vIp7\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}