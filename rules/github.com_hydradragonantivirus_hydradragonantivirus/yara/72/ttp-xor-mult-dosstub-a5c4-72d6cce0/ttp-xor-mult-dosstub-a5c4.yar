rule TTP_XOR_MULT_DOSStub_a5c4 {
  strings:
    $key_a5c4 = { f1 ac [2] 85 b4 [2] c2 b6 [2] 85 a7 [2] cb ab [2] c7 a1 [2] d0 aa [2] cb e4 [2] f6 }

  condition:
    any of them
}