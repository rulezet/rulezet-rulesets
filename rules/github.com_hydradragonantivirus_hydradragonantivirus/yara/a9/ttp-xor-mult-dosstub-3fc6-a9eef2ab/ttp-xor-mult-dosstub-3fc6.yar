rule TTP_XOR_MULT_DOSStub_3fc6 {
  strings:
    $key_3fc6 = { 6b ae [2] 1f b6 [2] 58 b4 [2] 1f a5 [2] 51 a9 [2] 5d a3 [2] 4a a8 [2] 51 e6 [2] 6c }

  condition:
    any of them
}