rule TTP_XOR_MULT_DOSStub_8ed9 {
  strings:
    $key_8ed9 = { da b1 [2] ae a9 [2] e9 ab [2] ae ba [2] e0 b6 [2] ec bc [2] fb b7 [2] e0 f9 [2] dd }

  condition:
    any of them
}