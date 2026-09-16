rule TTP_XOR_MULT_DOSStub_4cc6 {
  strings:
    $key_4cc6 = { 18 ae [2] 6c b6 [2] 2b b4 [2] 6c a5 [2] 22 a9 [2] 2e a3 [2] 39 a8 [2] 22 e6 [2] 1f }

  condition:
    any of them
}