rule TTP_XOR_MULT_DOSStub_ebc3 {
  strings:
    $key_ebc3 = { bf ab [2] cb b3 [2] 8c b1 [2] cb a0 [2] 85 ac [2] 89 a6 [2] 9e ad [2] 85 e3 [2] b8 }

  condition:
    any of them
}