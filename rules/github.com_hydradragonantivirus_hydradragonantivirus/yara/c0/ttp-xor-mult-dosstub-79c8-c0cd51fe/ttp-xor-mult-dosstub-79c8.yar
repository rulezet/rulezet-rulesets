rule TTP_XOR_MULT_DOSStub_79c8 {
  strings:
    $key_79c8 = { 2d a0 [2] 59 b8 [2] 1e ba [2] 59 ab [2] 17 a7 [2] 1b ad [2] 0c a6 [2] 17 e8 [2] 2a }

  condition:
    any of them
}