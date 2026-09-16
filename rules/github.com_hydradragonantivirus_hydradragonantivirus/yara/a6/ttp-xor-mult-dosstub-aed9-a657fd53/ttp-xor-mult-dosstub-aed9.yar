rule TTP_XOR_MULT_DOSStub_aed9 {
  strings:
    $key_aed9 = { fa b1 [2] 8e a9 [2] c9 ab [2] 8e ba [2] c0 b6 [2] cc bc [2] db b7 [2] c0 f9 [2] fd }

  condition:
    any of them
}