rule TTP_XOR_MULT_DOSStub_45c8 {
  strings:
    $key_45c8 = { 11 a0 [2] 65 b8 [2] 22 ba [2] 65 ab [2] 2b a7 [2] 27 ad [2] 30 a6 [2] 2b e8 [2] 16 }

  condition:
    any of them
}