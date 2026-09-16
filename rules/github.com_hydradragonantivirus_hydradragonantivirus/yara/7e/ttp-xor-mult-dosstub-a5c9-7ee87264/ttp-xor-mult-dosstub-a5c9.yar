rule TTP_XOR_MULT_DOSStub_a5c9 {
  strings:
    $key_a5c9 = { f1 a1 [2] 85 b9 [2] c2 bb [2] 85 aa [2] cb a6 [2] c7 ac [2] d0 a7 [2] cb e9 [2] f6 }

  condition:
    any of them
}