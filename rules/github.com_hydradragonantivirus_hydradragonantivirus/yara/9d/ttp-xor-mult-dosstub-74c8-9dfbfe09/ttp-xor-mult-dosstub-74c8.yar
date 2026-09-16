rule TTP_XOR_MULT_DOSStub_74c8 {
  strings:
    $key_74c8 = { 20 a0 [2] 54 b8 [2] 13 ba [2] 54 ab [2] 1a a7 [2] 16 ad [2] 01 a6 [2] 1a e8 [2] 27 }

  condition:
    any of them
}