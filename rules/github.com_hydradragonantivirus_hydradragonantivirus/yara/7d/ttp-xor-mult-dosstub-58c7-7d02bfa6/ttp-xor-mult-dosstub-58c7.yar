rule TTP_XOR_MULT_DOSStub_58c7 {
  strings:
    $key_58c7 = { 0c af [2] 78 b7 [2] 3f b5 [2] 78 a4 [2] 36 a8 [2] 3a a2 [2] 2d a9 [2] 36 e7 [2] 0b }

  condition:
    any of them
}