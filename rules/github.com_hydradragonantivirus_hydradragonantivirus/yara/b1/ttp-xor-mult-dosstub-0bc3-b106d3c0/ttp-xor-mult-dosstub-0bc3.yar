rule TTP_XOR_MULT_DOSStub_0bc3 {
  strings:
    $key_0bc3 = { 5f ab [2] 2b b3 [2] 6c b1 [2] 2b a0 [2] 65 ac [2] 69 a6 [2] 7e ad [2] 65 e3 [2] 58 }

  condition:
    any of them
}