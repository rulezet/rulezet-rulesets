rule TTP_XOR_MULT_DOSStub_7cc1 {
  strings:
    $key_7cc1 = { 28 a9 [2] 5c b1 [2] 1b b3 [2] 5c a2 [2] 12 ae [2] 1e a4 [2] 09 af [2] 12 e1 [2] 2f }

  condition:
    any of them
}