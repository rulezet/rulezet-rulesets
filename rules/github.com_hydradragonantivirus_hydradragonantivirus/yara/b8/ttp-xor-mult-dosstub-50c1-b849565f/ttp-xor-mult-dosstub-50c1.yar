rule TTP_XOR_MULT_DOSStub_50c1 {
  strings:
    $key_50c1 = { 04 a9 [2] 70 b1 [2] 37 b3 [2] 70 a2 [2] 3e ae [2] 32 a4 [2] 25 af [2] 3e e1 [2] 03 }

  condition:
    any of them
}