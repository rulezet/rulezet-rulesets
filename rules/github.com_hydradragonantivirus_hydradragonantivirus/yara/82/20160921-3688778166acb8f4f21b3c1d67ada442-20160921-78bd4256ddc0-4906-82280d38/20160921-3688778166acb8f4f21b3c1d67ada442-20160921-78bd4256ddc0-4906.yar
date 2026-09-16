rule _20160921_3688778166acb8f4f21b3c1d67ada442_20160921_78bd4256ddc0_4906 {
  meta:
    description = "datamaliciousorder - from files 20160921_3688778166acb8f4f21b3c1d67ada442.js, 20160921_78bd4256ddc0b384791a12e8ab1fd8a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03559b6095f398f17a62ec1f50c0a70c4b4074a67f6b8e3a51dfe026b238b085"
    hash2       = "c64d081235a424574ab6bbe64470cbee71a700f01b638afac6d0954ebc5cc0a0"

  strings:
    $s1 = "function fuck(){return \"YAv\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){ret" ascii
    $s2 = "ck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Ik" ascii
    $s3 = "){return \"Np\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Za\";})(" ascii
    $s4 = " \"YQt\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IRn\";})(),(fun" ascii
    $s5 = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}