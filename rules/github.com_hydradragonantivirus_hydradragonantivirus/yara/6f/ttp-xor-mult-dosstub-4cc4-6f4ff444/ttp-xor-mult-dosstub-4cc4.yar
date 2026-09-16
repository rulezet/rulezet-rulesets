rule TTP_XOR_MULT_DOSStub_4cc4 {
  strings:
    $key_4cc4 = { 18 ac [2] 6c b4 [2] 2b b6 [2] 6c a7 [2] 22 ab [2] 2e a1 [2] 39 aa [2] 22 e4 [2] 1f }

  condition:
    any of them
}