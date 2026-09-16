rule TTP_XOR_MULT_DOSStub_58c6 {
  strings:
    $key_58c6 = { 0c ae [2] 78 b6 [2] 3f b4 [2] 78 a5 [2] 36 a9 [2] 3a a3 [2] 2d a8 [2] 36 e6 [2] 0b }

  condition:
    any of them
}