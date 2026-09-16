rule TTP_XOR_MULT_DOSStub_a587 {
  strings:
    $key_a587 = { f1 ef [2] 85 f7 [2] c2 f5 [2] 85 e4 [2] cb e8 [2] c7 e2 [2] d0 e9 [2] cb a7 [2] f6 }

  condition:
    any of them
}