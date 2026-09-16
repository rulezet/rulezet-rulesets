rule TTP_XOR_MULT_DOSStub_01c6 {
  strings:
    $key_01c6 = { 55 ae [2] 21 b6 [2] 66 b4 [2] 21 a5 [2] 6f a9 [2] 63 a3 [2] 74 a8 [2] 6f e6 [2] 52 }

  condition:
    any of them
}