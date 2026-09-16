rule TTP_XOR_MULT_DOSStub_6fa6 {
  strings:
    $key_6fa6 = { 3b ce [2] 4f d6 [2] 08 d4 [2] 4f c5 [2] 01 c9 [2] 0d c3 [2] 1a c8 [2] 01 86 [2] 3c }

  condition:
    any of them
}