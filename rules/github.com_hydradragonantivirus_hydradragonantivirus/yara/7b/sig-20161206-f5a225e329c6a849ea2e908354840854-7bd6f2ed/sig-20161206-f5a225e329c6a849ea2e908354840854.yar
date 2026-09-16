rule sig_20161206_f5a225e329c6a849ea2e908354840854 {
  meta:
    description = "datamaliciousorder - file 20161206_f5a225e329c6a849ea2e908354840854.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fefda3e77557b6fb166ae8fdd025f422e0a07e9f45bf0de5d2d64be4d9335456"

  strings:
    $s1 = "var vIXk0 = new Function(\"s\", '{var vJn4 = new Date();vJn4[\"setUTCFullYear\"](\"2003\");if (vJn4.getUTCFullYear().toString(10" ascii
    $s2 = "var vIXk0 = new Function(\"s\", '{var vJn4 = new Date();vJn4[\"setUTCFullYear\"](\"2003\");if (vJn4.getUTCFullYear().toString(10" ascii
    $s3 = "function vQTq9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "2003\") {var vFd1 = s.split(\"##\"); return vFd1.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}