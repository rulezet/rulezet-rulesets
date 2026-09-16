rule TTP_XOR_MULT_DOSStub_01c7 {
  strings:
    $key_01c7 = { 55 af [2] 21 b7 [2] 66 b5 [2] 21 a4 [2] 6f a8 [2] 63 a2 [2] 74 a9 [2] 6f e7 [2] 52 }

  condition:
    any of them
}