rule TTP_XOR_MULT_DOSStub_04c8 {
  strings:
    $key_04c8 = { 50 a0 [2] 24 b8 [2] 63 ba [2] 24 ab [2] 6a a7 [2] 66 ad [2] 71 a6 [2] 6a e8 [2] 57 }

  condition:
    any of them
}