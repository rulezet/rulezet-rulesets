rule TTP_XOR_MULT_DOSStub_5cc1 {
  strings:
    $key_5cc1 = { 08 a9 [2] 7c b1 [2] 3b b3 [2] 7c a2 [2] 32 ae [2] 3e a4 [2] 29 af [2] 32 e1 [2] 0f }

  condition:
    any of them
}