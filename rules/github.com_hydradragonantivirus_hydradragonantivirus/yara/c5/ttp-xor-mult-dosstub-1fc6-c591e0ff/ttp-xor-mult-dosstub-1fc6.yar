rule TTP_XOR_MULT_DOSStub_1fc6 {
  strings:
    $key_1fc6 = { 4b ae [2] 3f b6 [2] 78 b4 [2] 3f a5 [2] 71 a9 [2] 7d a3 [2] 6a a8 [2] 71 e6 [2] 4c }

  condition:
    any of them
}