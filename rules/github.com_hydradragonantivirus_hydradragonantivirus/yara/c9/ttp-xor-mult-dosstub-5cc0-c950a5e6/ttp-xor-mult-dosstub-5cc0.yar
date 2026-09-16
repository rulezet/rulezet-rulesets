rule TTP_XOR_MULT_DOSStub_5cc0 {
  strings:
    $key_5cc0 = { 08 a8 [2] 7c b0 [2] 3b b2 [2] 7c a3 [2] 32 af [2] 3e a5 [2] 29 ae [2] 32 e0 [2] 0f }

  condition:
    any of them
}