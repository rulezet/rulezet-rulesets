rule TTP_XOR_MULT_DOSStub_2bc4 {
  strings:
    $key_2bc4 = { 7f ac [2] 0b b4 [2] 4c b6 [2] 0b a7 [2] 45 ab [2] 49 a1 [2] 5e aa [2] 45 e4 [2] 78 }

  condition:
    any of them
}