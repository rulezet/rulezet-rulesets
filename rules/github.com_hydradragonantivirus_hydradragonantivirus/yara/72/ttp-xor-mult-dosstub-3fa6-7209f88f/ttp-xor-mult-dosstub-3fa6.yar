rule TTP_XOR_MULT_DOSStub_3fa6 {
  strings:
    $key_3fa6 = { 6b ce [2] 1f d6 [2] 58 d4 [2] 1f c5 [2] 51 c9 [2] 5d c3 [2] 4a c8 [2] 51 86 [2] 6c }

  condition:
    any of them
}