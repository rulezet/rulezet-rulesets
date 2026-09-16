rule TTP_XOR_MULT_DOSStub_4987 {
  strings:
    $key_4987 = { 1d ef [2] 69 f7 [2] 2e f5 [2] 69 e4 [2] 27 e8 [2] 2b e2 [2] 3c e9 [2] 27 a7 [2] 1a }

  condition:
    any of them
}