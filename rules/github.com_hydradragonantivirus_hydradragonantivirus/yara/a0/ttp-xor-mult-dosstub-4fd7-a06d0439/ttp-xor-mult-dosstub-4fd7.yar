rule TTP_XOR_MULT_DOSStub_4fd7 {
  strings:
    $key_4fd7 = { 1b bf [2] 6f a7 [2] 28 a5 [2] 6f b4 [2] 21 b8 [2] 2d b2 [2] 3a b9 [2] 21 f7 [2] 1c }

  condition:
    any of them
}