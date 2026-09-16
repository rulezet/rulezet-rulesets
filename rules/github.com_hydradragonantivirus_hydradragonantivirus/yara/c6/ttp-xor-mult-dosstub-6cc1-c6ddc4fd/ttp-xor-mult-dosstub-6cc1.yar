rule TTP_XOR_MULT_DOSStub_6cc1 {
  strings:
    $key_6cc1 = { 38 a9 [2] 4c b1 [2] 0b b3 [2] 4c a2 [2] 02 ae [2] 0e a4 [2] 19 af [2] 02 e1 [2] 3f }

  condition:
    any of them
}