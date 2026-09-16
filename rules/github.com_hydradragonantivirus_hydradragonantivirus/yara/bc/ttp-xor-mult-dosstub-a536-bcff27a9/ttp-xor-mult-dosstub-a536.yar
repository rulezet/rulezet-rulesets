rule TTP_XOR_MULT_DOSStub_a536 {
  strings:
    $key_a536 = { f1 5e [2] 85 46 [2] c2 44 [2] 85 55 [2] cb 59 [2] c7 53 [2] d0 58 [2] cb 16 [2] f6 }

  condition:
    any of them
}