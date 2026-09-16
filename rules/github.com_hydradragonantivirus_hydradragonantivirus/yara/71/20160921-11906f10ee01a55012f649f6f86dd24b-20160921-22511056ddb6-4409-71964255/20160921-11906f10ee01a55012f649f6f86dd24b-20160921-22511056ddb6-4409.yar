rule _20160921_11906f10ee01a55012f649f6f86dd24b_20160921_22511056ddb6_4409 {
  meta:
    description = "datamaliciousorder - from files 20160921_11906f10ee01a55012f649f6f86dd24b.js, 20160921_22511056ddb6d59ffb3e56c3b7382182.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7e3d843ddea21ba91cad5bd21d3e536f69426d4c4c5a060bbfe7f1f967bda27"
    hash2       = "1a5f7b2bfdf24defc0d363114441d0c0a0452fd599bf21d359b1b5f068dfc567"

  strings:
    $s1 = "MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(functi" ascii
    $s2 = "\"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GWo\";})(),(fun" ascii
    $s3 = "eturn \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})()" ascii
    $s4 = "urn \"Ml\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(f" ascii
    $s5 = "function fuck(){return \"YQt\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}