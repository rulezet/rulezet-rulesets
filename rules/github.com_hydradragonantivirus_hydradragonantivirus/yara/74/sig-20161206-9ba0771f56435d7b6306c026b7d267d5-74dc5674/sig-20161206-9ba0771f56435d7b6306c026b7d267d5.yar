rule sig_20161206_9ba0771f56435d7b6306c026b7d267d5 {
  meta:
    description = "datamaliciousorder - file 20161206_9ba0771f56435d7b6306c026b7d267d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3b75574e6896bc63ee3af406b1987df351521873dfe09ce07cbc8e4edaaa496"

  strings:
    $s1 = "var vGm3 = new Function(\"s\", '{var vEp4 = new Date();vEp4[\"setUTCFullYear\"](\"2003\");if (vEp4.getUTCFullYear().toString(10)" ascii
    $s2 = "var vGm3 = new Function(\"s\", '{var vEp4 = new Date();vEp4[\"setUTCFullYear\"](\"2003\");if (vEp4.getUTCFullYear().toString(10)" ascii
    $s3 = "function vIRq2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "003\") {var vZQo7 = s.split(\"##\"); return vZQo7.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}