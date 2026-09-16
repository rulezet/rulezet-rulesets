rule TTP_XOR_MULT_DOSStub_6fc6 {
  strings:
    $key_6fc6 = { 3b ae [2] 4f b6 [2] 08 b4 [2] 4f a5 [2] 01 a9 [2] 0d a3 [2] 1a a8 [2] 01 e6 [2] 3c }

  condition:
    any of them
}