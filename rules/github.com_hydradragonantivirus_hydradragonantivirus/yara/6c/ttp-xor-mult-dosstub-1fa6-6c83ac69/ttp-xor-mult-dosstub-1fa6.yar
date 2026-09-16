rule TTP_XOR_MULT_DOSStub_1fa6 {
  strings:
    $key_1fa6 = { 4b ce [2] 3f d6 [2] 78 d4 [2] 3f c5 [2] 71 c9 [2] 7d c3 [2] 6a c8 [2] 71 86 [2] 4c }

  condition:
    any of them
}