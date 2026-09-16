rule TTP_XOR_MULT_DOSStub_6bc3 {
  strings:
    $key_6bc3 = { 3f ab [2] 4b b3 [2] 0c b1 [2] 4b a0 [2] 05 ac [2] 09 a6 [2] 1e ad [2] 05 e3 [2] 38 }

  condition:
    any of them
}