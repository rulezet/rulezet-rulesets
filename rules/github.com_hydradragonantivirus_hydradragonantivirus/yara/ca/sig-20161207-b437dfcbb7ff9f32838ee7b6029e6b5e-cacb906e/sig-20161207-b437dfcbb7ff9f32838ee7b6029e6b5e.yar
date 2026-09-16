rule sig_20161207_b437dfcbb7ff9f32838ee7b6029e6b5e {
  meta:
    description = "datamaliciousorder - file 20161207_b437dfcbb7ff9f32838ee7b6029e6b5e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92938c5a9b2b6ded49e670dcab66dd22850d6219e469ed9af2023b361a0884b3"

  strings:
    $s1 = " new Date();vCe2[\"setUTCFullYear\"](\"2003\");if (vCe2.getUTCFullYear().toString(10) == \"2003\") {var vOn2 = vCn8.split(\"####" ascii
    $s2 = "var vFOp1 = new Function(\"vCn8\", '{return vCn8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYFc6 = new Function(\"vCn8" ascii
    $s3 = "urn vOn2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vFOp1 = new Function(\"vCn8\", '{return vCn8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vYFc6 = new Function(\"vCn8" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}