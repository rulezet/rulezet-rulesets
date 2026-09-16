rule TTP_XOR_MULT_DOSStub_7cc7 {
  strings:
    $key_7cc7 = { 28 af [2] 5c b7 [2] 1b b5 [2] 5c a4 [2] 12 a8 [2] 1e a2 [2] 09 a9 [2] 12 e7 [2] 2f }

  condition:
    any of them
}