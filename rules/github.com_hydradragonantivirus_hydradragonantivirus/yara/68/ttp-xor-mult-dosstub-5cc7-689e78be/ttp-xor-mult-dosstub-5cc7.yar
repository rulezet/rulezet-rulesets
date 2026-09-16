rule TTP_XOR_MULT_DOSStub_5cc7 {
  strings:
    $key_5cc7 = { 08 af [2] 7c b7 [2] 3b b5 [2] 7c a4 [2] 32 a8 [2] 3e a2 [2] 29 a9 [2] 32 e7 [2] 0f }

  condition:
    any of them
}