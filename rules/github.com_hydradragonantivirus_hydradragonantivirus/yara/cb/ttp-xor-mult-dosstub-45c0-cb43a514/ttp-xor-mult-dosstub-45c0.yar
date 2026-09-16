rule TTP_XOR_MULT_DOSStub_45c0 {
  strings:
    $key_45c0 = { 11 a8 [2] 65 b0 [2] 22 b2 [2] 65 a3 [2] 2b af [2] 27 a5 [2] 30 ae [2] 2b e0 [2] 16 }

  condition:
    any of them
}