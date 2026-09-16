rule TTP_XOR_MULT_DOSStub_4fd9 {
  strings:
    $key_4fd9 = { 1b b1 [2] 6f a9 [2] 28 ab [2] 6f ba [2] 21 b6 [2] 2d bc [2] 3a b7 [2] 21 f9 [2] 1c }

  condition:
    any of them
}