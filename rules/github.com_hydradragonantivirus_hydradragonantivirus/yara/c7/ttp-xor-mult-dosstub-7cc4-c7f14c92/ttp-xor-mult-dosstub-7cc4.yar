rule TTP_XOR_MULT_DOSStub_7cc4 {
  strings:
    $key_7cc4 = { 28 ac [2] 5c b4 [2] 1b b6 [2] 5c a7 [2] 12 ab [2] 1e a1 [2] 09 aa [2] 12 e4 [2] 2f }

  condition:
    any of them
}