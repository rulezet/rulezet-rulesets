rule TTP_XOR_MULT_DOSStub_7fa7 {
  strings:
    $key_7fa7 = { 2b cf [2] 5f d7 [2] 18 d5 [2] 5f c4 [2] 11 c8 [2] 1d c2 [2] 0a c9 [2] 11 87 [2] 2c }

  condition:
    any of them
}