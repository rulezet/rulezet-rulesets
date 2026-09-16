rule TTP_XOR_MULT_DOSStub_5cc3 {
  strings:
    $key_5cc3 = { 08 ab [2] 7c b3 [2] 3b b1 [2] 7c a0 [2] 32 ac [2] 3e a6 [2] 29 ad [2] 32 e3 [2] 0f }

  condition:
    any of them
}