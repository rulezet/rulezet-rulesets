rule TTP_XOR_MULT_DOSStub_6fc7 {
  strings:
    $key_6fc7 = { 3b af [2] 4f b7 [2] 08 b5 [2] 4f a4 [2] 01 a8 [2] 0d a2 [2] 1a a9 [2] 01 e7 [2] 3c }

  condition:
    any of them
}