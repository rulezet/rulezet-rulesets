rule TTP_XOR_MULT_DOSStub_3cc3 {
  strings:
    $key_3cc3 = { 68 ab [2] 1c b3 [2] 5b b1 [2] 1c a0 [2] 52 ac [2] 5e a6 [2] 49 ad [2] 52 e3 [2] 6f }

  condition:
    any of them
}