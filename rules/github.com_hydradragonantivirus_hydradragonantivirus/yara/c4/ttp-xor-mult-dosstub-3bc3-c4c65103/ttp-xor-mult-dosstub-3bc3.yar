rule TTP_XOR_MULT_DOSStub_3bc3 {
  strings:
    $key_3bc3 = { 6f ab [2] 1b b3 [2] 5c b1 [2] 1b a0 [2] 55 ac [2] 59 a6 [2] 4e ad [2] 55 e3 [2] 68 }

  condition:
    any of them
}