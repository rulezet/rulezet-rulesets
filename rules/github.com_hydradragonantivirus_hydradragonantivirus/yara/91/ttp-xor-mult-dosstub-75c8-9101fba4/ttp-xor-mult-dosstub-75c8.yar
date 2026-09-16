rule TTP_XOR_MULT_DOSStub_75c8 {
  strings:
    $key_75c8 = { 21 a0 [2] 55 b8 [2] 12 ba [2] 55 ab [2] 1b a7 [2] 17 ad [2] 00 a6 [2] 1b e8 [2] 26 }

  condition:
    any of them
}