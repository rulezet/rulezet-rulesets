rule TTP_XOR_MULT_DOSStub_a546 {
  strings:
    $key_a546 = { f1 2e [2] 85 36 [2] c2 34 [2] 85 25 [2] cb 29 [2] c7 23 [2] d0 28 [2] cb 66 [2] f6 }

  condition:
    any of them
}