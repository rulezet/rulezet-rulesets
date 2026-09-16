rule _20160921_cebdb99ce2e54d24acef5b8ee0096562_20160921_f9054cc04d83_4062 {
  meta:
    description = "datamaliciousorder - from files 20160921_cebdb99ce2e54d24acef5b8ee0096562.js, 20160921_f9054cc04d83c2e4156f98873a8df799.js, 20160921_fbc9133aa5350aa4ce872cb5927c8f4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87071d18d308dc7717dabe03dc0d11efe7ee7231e95d9fca71e480f5f2430f7d"
    hash2       = "7cfaa97d52690e3fa38d039126186e468701b138b24622f48887707d5da022f0"
    hash3       = "520ea6f275b172709ff81bfec4d8a5a9f734ab080b25e7c50bfe2a36800af6e3"

  strings:
    $s1 = "p\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vj\";})(),(function" ascii
    $s2 = ",(function f000(){return \"Oe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s3 = " f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"DY" ascii
    $s4 = "\"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"BMj\";})(),(fun" ascii
    $s5 = "(function f000(){return \"PTi\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s6 = "\"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"BQb\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}