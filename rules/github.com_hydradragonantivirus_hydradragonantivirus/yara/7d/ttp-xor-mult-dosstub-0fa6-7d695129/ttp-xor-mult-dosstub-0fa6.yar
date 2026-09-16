rule TTP_XOR_MULT_DOSStub_0fa6 {
  strings:
    $key_0fa6 = { 5b ce [2] 2f d6 [2] 68 d4 [2] 2f c5 [2] 61 c9 [2] 6d c3 [2] 7a c8 [2] 61 86 [2] 5c }

  condition:
    any of them
}