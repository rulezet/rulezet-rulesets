rule TTP_XOR_MULT_DOSStub_7fa6 {
  strings:
    $key_7fa6 = { 2b ce [2] 5f d6 [2] 18 d4 [2] 5f c5 [2] 11 c9 [2] 1d c3 [2] 0a c8 [2] 11 86 [2] 2c }

  condition:
    any of them
}