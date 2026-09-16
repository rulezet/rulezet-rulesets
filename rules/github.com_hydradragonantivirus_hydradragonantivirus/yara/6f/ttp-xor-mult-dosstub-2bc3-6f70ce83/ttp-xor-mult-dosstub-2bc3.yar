rule TTP_XOR_MULT_DOSStub_2bc3 {
  strings:
    $key_2bc3 = { 7f ab [2] 0b b3 [2] 4c b1 [2] 0b a0 [2] 45 ac [2] 49 a6 [2] 5e ad [2] 45 e3 [2] 78 }

  condition:
    any of them
}