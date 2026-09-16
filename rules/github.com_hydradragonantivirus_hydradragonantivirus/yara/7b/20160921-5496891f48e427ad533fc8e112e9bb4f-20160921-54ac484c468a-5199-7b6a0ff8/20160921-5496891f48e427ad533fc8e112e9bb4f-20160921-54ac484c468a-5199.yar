rule _20160921_5496891f48e427ad533fc8e112e9bb4f_20160921_54ac484c468a_5199 {
  meta:
    description = "datamaliciousorder - from files 20160921_5496891f48e427ad533fc8e112e9bb4f.js, 20160921_54ac484c468ac2ca7fe6c7210ca717bb.js, 20160921_f9054cc04d83c2e4156f98873a8df799.js, 20160921_fbc9133aa5350aa4ce872cb5927c8f4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb85e1d59ed8f9cee344ab5ab95f651cb8fb1ee7ec35d0a88f8f41279a3d17a6"
    hash2       = "5b883334540a4216b3582d1f2fa0a27f21b9c64a87944c8e58d9fab0f609eef3"
    hash3       = "7cfaa97d52690e3fa38d039126186e468701b138b24622f48887707d5da022f0"
    hash4       = "520ea6f275b172709ff81bfec4d8a5a9f734ab080b25e7c50bfe2a36800af6e3"

  strings:
    $s1 = "0(){return \"ZIi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\"" ascii
    $s2 = "nction f000(){return \"Qa\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DIa\";})(),(function f000(){retu" ascii
    $s3 = "){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"NBs\";" ascii
    $s4 = "b\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s5 = "unction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}