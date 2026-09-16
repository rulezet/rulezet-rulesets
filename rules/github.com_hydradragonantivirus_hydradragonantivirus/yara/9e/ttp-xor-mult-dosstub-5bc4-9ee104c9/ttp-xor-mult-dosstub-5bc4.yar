rule TTP_XOR_MULT_DOSStub_5bc4 {
  strings:
    $key_5bc4 = { 0f ac [2] 7b b4 [2] 3c b6 [2] 7b a7 [2] 35 ab [2] 39 a1 [2] 2e aa [2] 35 e4 [2] 08 }

  condition:
    any of them
}