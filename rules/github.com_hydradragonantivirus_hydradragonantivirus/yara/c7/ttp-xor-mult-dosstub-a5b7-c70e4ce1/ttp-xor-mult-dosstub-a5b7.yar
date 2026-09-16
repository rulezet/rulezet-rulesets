rule TTP_XOR_MULT_DOSStub_a5b7 {
  strings:
    $key_a5b7 = { f1 df [2] 85 c7 [2] c2 c5 [2] 85 d4 [2] cb d8 [2] c7 d2 [2] d0 d9 [2] cb 97 [2] f6 }

  condition:
    any of them
}