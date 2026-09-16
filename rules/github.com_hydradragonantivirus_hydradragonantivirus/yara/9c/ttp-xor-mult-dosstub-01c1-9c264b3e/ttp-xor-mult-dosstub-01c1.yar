rule TTP_XOR_MULT_DOSStub_01c1 {
  strings:
    $key_01c1 = { 55 a9 [2] 21 b1 [2] 66 b3 [2] 21 a2 [2] 6f ae [2] 63 a4 [2] 74 af [2] 6f e1 [2] 52 }

  condition:
    any of them
}