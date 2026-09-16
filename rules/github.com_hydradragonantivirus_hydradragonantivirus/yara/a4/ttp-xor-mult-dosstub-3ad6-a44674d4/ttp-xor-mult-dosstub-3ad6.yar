rule TTP_XOR_MULT_DOSStub_3ad6 {
  strings:
    $key_3ad6 = { 6e be [2] 1a a6 [2] 5d a4 [2] 1a b5 [2] 54 b9 [2] 58 b3 [2] 4f b8 [2] 54 f6 [2] 69 }

  condition:
    any of them
}