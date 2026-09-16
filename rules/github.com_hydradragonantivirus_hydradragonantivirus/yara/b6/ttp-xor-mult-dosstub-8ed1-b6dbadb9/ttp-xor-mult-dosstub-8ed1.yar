rule TTP_XOR_MULT_DOSStub_8ed1 {
  strings:
    $key_8ed1 = { da b9 [2] ae a1 [2] e9 a3 [2] ae b2 [2] e0 be [2] ec b4 [2] fb bf [2] e0 f1 [2] dd }

  condition:
    any of them
}