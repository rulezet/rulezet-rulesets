rule TTP_XOR_MULT_DOSStub_71c7 {
  strings:
    $key_71c7 = { 25 af [2] 51 b7 [2] 16 b5 [2] 51 a4 [2] 1f a8 [2] 13 a2 [2] 04 a9 [2] 1f e7 [2] 22 }

  condition:
    any of them
}