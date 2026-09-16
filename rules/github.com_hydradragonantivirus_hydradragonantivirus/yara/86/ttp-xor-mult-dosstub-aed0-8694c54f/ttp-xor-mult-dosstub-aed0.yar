rule TTP_XOR_MULT_DOSStub_aed0 {
  strings:
    $key_aed0 = { fa b8 [2] 8e a0 [2] c9 a2 [2] 8e b3 [2] c0 bf [2] cc b5 [2] db be [2] c0 f0 [2] fd }

  condition:
    any of them
}