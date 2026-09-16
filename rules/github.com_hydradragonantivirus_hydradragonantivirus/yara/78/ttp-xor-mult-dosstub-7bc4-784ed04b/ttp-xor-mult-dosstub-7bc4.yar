rule TTP_XOR_MULT_DOSStub_7bc4 {
  strings:
    $key_7bc4 = { 2f ac [2] 5b b4 [2] 1c b6 [2] 5b a7 [2] 15 ab [2] 19 a1 [2] 0e aa [2] 15 e4 [2] 28 }

  condition:
    any of them
}