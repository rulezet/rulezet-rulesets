rule TTP_XOR_MULT_DOSStub_71c1 {
  strings:
    $key_71c1 = { 25 a9 [2] 51 b1 [2] 16 b3 [2] 51 a2 [2] 1f ae [2] 13 a4 [2] 04 af [2] 1f e1 [2] 22 }

  condition:
    any of them
}