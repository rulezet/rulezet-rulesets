rule TTP_XOR_MULT_DOSStub_1cc3 {
  strings:
    $key_1cc3 = { 48 ab [2] 3c b3 [2] 7b b1 [2] 3c a0 [2] 72 ac [2] 7e a6 [2] 69 ad [2] 72 e3 [2] 4f }

  condition:
    any of them
}