rule TTP_XOR_MULT_DOSStub_22c8 {
  strings:
    $key_22c8 = { 76 a0 [2] 02 b8 [2] 45 ba [2] 02 ab [2] 4c a7 [2] 40 ad [2] 57 a6 [2] 4c e8 [2] 71 }

  condition:
    any of them
}