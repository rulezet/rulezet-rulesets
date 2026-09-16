rule TTP_XOR_MULT_DOSStub_a5c2 {
  strings:
    $key_a5c2 = { f1 aa [2] 85 b2 [2] c2 b0 [2] 85 a1 [2] cb ad [2] c7 a7 [2] d0 ac [2] cb e2 [2] f6 }

  condition:
    any of them
}