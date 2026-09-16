rule _20160921_1c0508ced9fad1614d80fce90a3209ed_20160921_8ac006dedc62_1545 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c0508ced9fad1614d80fce90a3209ed.js, 20160921_8ac006dedc6205f05757feeef6cd894a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e27406e32c891781b5403c718c4f32d67f6580cf6f952a30d0c6452ab9775a4c"
    hash2       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"

  strings:
    $s1  = "f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn" ascii
    $s2  = "n f000(){return \"ZIi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"" ascii
    $s3  = "0(){return \"Nx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii
    $s4  = "turn \"Sj\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(f" ascii
    $s5  = "\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f" ascii
    $s6  = "(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Yi\";}" ascii
    $s7  = "rn \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Do\";})(),(f" ascii
    $s8  = "return \"Vu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})()," ascii
    $s9  = "Qb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function" ascii
    $s10 = "\"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"RLk\";})(),(func" ascii
    $s11 = "MDb\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s12 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oe\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}