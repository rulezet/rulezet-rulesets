rule TTP_XOR_MULT_DOSStub_14c8 {
  strings:
    $key_14c8 = { 40 a0 [2] 34 b8 [2] 73 ba [2] 34 ab [2] 7a a7 [2] 76 ad [2] 61 a6 [2] 7a e8 [2] 47 }

  condition:
    any of them
}