rule TTP_XOR_MULT_DOSStub_56c8 {
  strings:
    $key_56c8 = { 02 a0 [2] 76 b8 [2] 31 ba [2] 76 ab [2] 38 a7 [2] 34 ad [2] 23 a6 [2] 38 e8 [2] 05 }

  condition:
    any of them
}