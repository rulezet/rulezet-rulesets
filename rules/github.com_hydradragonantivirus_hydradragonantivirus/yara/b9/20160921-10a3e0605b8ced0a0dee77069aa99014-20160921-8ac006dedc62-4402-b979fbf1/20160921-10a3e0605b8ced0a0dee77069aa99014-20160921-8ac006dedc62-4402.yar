rule _20160921_10a3e0605b8ced0a0dee77069aa99014_20160921_8ac006dedc62_4402 {
  meta:
    description = "datamaliciousorder - from files 20160921_10a3e0605b8ced0a0dee77069aa99014.js, 20160921_8ac006dedc6205f05757feeef6cd894a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "462b92b513dfa104fe3c095cbf98c34389b13ed004671baf4f95430e8487a108"
    hash2       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"

  strings:
    $s1 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"HJm\";})(),(function f" ascii
    $s2 = "return \"Mt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()" ascii
    $s3 = "eturn \"Qa\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s4 = "ction f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTi\";})(),(function f000(){retur" ascii
    $s5 = "on f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}