rule TTP_XOR_MULT_DOSStub_3cc7 {
  strings:
    $key_3cc7 = { 68 af [2] 1c b7 [2] 5b b5 [2] 1c a4 [2] 52 a8 [2] 5e a2 [2] 49 a9 [2] 52 e7 [2] 6f }

  condition:
    any of them
}