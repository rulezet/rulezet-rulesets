rule TTP_XOR_MULT_DOSStub_1bc3 {
  strings:
    $key_1bc3 = { 4f ab [2] 3b b3 [2] 7c b1 [2] 3b a0 [2] 75 ac [2] 79 a6 [2] 6e ad [2] 75 e3 [2] 48 }

  condition:
    any of them
}