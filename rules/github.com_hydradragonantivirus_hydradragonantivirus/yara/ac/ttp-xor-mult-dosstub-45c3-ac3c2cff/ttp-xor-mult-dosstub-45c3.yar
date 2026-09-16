rule TTP_XOR_MULT_DOSStub_45c3 {
  strings:
    $key_45c3 = { 11 ab [2] 65 b3 [2] 22 b1 [2] 65 a0 [2] 2b ac [2] 27 a6 [2] 30 ad [2] 2b e3 [2] 16 }

  condition:
    any of them
}