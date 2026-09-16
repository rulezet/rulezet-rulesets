rule TTP_XOR_MULT_DOSStub_a580 {
  strings:
    $key_a580 = { f1 e8 [2] 85 f0 [2] c2 f2 [2] 85 e3 [2] cb ef [2] c7 e5 [2] d0 ee [2] cb a0 [2] f6 }

  condition:
    any of them
}