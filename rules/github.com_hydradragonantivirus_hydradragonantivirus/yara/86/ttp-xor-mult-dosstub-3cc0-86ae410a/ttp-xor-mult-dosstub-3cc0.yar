rule TTP_XOR_MULT_DOSStub_3cc0 {
  strings:
    $key_3cc0 = { 68 a8 [2] 1c b0 [2] 5b b2 [2] 1c a3 [2] 52 af [2] 5e a5 [2] 49 ae [2] 52 e0 [2] 6f }

  condition:
    any of them
}