rule TTP_XOR_MULT_DOSStub_52c8 {
  strings:
    $key_52c8 = { 06 a0 [2] 72 b8 [2] 35 ba [2] 72 ab [2] 3c a7 [2] 30 ad [2] 27 a6 [2] 3c e8 [2] 01 }

  condition:
    any of them
}