rule TTP_XOR_MULT_DOSStub_17c8 {
  strings:
    $key_17c8 = { 43 a0 [2] 37 b8 [2] 70 ba [2] 37 ab [2] 79 a7 [2] 75 ad [2] 62 a6 [2] 79 e8 [2] 44 }

  condition:
    any of them
}