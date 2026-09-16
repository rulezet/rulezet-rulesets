rule TTP_XOR_MULT_DOSStub_58c1 {
  strings:
    $key_58c1 = { 0c a9 [2] 78 b1 [2] 3f b3 [2] 78 a2 [2] 36 ae [2] 3a a4 [2] 2d af [2] 36 e1 [2] 0b }

  condition:
    any of them
}