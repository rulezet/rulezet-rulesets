rule TTP_XOR_MULT_DOSStub_5fc6 {
  strings:
    $key_5fc6 = { 0b ae [2] 7f b6 [2] 38 b4 [2] 7f a5 [2] 31 a9 [2] 3d a3 [2] 2a a8 [2] 31 e6 [2] 0c }

  condition:
    any of them
}