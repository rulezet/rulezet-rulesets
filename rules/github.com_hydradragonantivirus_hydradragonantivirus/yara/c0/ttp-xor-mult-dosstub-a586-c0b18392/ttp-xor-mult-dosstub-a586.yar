rule TTP_XOR_MULT_DOSStub_a586 {
  strings:
    $key_a586 = { f1 ee [2] 85 f6 [2] c2 f4 [2] 85 e5 [2] cb e9 [2] c7 e3 [2] d0 e8 [2] cb a6 [2] f6 }

  condition:
    any of them
}