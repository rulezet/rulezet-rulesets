rule TTP_XOR_MULT_DOSStub_8ed6 {
  strings:
    $key_8ed6 = { da be [2] ae a6 [2] e9 a4 [2] ae b5 [2] e0 b9 [2] ec b3 [2] fb b8 [2] e0 f6 [2] dd }

  condition:
    any of them
}