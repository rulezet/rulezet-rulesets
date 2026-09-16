rule TTP_XOR_MULT_DOSStub_5ac1 {
  strings:
    $key_5ac1 = { 0e a9 [2] 7a b1 [2] 3d b3 [2] 7a a2 [2] 34 ae [2] 38 a4 [2] 2f af [2] 34 e1 [2] 09 }

  condition:
    any of them
}