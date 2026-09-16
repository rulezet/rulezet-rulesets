rule TTP_XOR_MULT_DOSStub_a537 {
  strings:
    $key_a537 = { f1 5f [2] 85 47 [2] c2 45 [2] 85 54 [2] cb 58 [2] c7 52 [2] d0 59 [2] cb 17 [2] f6 }

  condition:
    any of them
}