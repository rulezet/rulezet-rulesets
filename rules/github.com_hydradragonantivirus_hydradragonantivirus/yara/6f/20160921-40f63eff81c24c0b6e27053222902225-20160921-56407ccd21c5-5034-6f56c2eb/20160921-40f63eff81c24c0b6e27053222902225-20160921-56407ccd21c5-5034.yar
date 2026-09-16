rule _20160921_40f63eff81c24c0b6e27053222902225_20160921_56407ccd21c5_5034 {
  meta:
    description = "datamaliciousorder - from files 20160921_40f63eff81c24c0b6e27053222902225.js, 20160921_56407ccd21c5f8f4947d4df222e60442.js, 20160921_d44650cb742ce4feede24ebce4407e1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b71d253d7ac7dfb797132caac458cf74b81e67304218edbb764243d89e51bb1"
    hash2       = "bec8a0189f43e097fc0815a0bb39f2df50e4c37c7185ad70b3be3b0d17b8dd32"
    hash3       = "5d3f7264c4109728074b6f96ac9910bb0072014149731ab6e6b307d40d5c37ff"

  strings:
    $s1 = "unction fuck(){return \"Cd\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s2 = "Rx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"We\";})(),(function" ascii
    $s3 = " \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(fun" ascii
    $s4 = "nction fuck(){return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s5 = "tion fuck(){return \"Vf\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}