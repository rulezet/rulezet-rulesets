rule _20160921_68d4a1cff7c2dbc758cf0077184d0d52_20160921_74aa1eb054c4_5338 {
  meta:
    description = "datamaliciousorder - from files 20160921_68d4a1cff7c2dbc758cf0077184d0d52.js, 20160921_74aa1eb054c4d9cf85bcad2468e8404a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d2799f014910856c25b225165971fbe59cf99c8eb1db930d774de46f64d76c2"
    hash2       = "74bb8f886c1de9aea157cf5ee2e1b8c02b30df1117e95e18ef3a2d5dc44277ad"

  strings:
    $s1 = " f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"T" ascii
    $s2 = "unction f000(){return \"Nx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s3 = "urn \"ZFe\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s4 = "function f000(){return \"Nv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"RPt\";})(),(function f000(){ret" ascii
    $s5 = " \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"YTp\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}