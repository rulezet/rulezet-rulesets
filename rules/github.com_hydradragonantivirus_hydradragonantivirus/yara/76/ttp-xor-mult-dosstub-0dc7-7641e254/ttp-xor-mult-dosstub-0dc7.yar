rule TTP_XOR_MULT_DOSStub_0dc7 {
  strings:
    $key_0dc7 = { 59 af [2] 2d b7 [2] 6a b5 [2] 2d a4 [2] 63 a8 [2] 6f a2 [2] 78 a9 [2] 63 e7 [2] 5e }

  condition:
    any of them
}