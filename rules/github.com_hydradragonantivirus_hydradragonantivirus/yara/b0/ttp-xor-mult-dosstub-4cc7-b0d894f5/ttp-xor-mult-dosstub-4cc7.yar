rule TTP_XOR_MULT_DOSStub_4cc7 {
  strings:
    $key_4cc7 = { 18 af [2] 6c b7 [2] 2b b5 [2] 6c a4 [2] 22 a8 [2] 2e a2 [2] 39 a9 [2] 22 e7 [2] 1f }

  condition:
    any of them
}