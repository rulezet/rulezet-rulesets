rule TTP_XOR_MULT_DOSStub_41c7 {
  strings:
    $key_41c7 = { 15 af [2] 61 b7 [2] 26 b5 [2] 61 a4 [2] 2f a8 [2] 23 a2 [2] 34 a9 [2] 2f e7 [2] 12 }

  condition:
    any of them
}