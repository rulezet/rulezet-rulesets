rule TTP_XOR_MULT_DOSStub_4cc0 {
  strings:
    $key_4cc0 = { 18 a8 [2] 6c b0 [2] 2b b2 [2] 6c a3 [2] 22 af [2] 2e a5 [2] 39 ae [2] 22 e0 [2] 1f }

  condition:
    any of them
}