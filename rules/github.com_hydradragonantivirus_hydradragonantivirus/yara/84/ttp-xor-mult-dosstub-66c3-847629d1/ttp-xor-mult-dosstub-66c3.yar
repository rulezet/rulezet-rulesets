rule TTP_XOR_MULT_DOSStub_66c3 {
  strings:
    $key_66c3 = { 32 ab [2] 46 b3 [2] 01 b1 [2] 46 a0 [2] 08 ac [2] 04 a6 [2] 13 ad [2] 08 e3 [2] 35 }

  condition:
    any of them
}