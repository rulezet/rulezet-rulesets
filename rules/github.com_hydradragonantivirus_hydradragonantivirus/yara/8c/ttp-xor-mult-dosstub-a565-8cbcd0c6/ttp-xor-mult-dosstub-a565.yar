rule TTP_XOR_MULT_DOSStub_a565 {
  strings:
    $key_a565 = { f1 0d [2] 85 15 [2] c2 17 [2] 85 06 [2] cb 0a [2] c7 00 [2] d0 0b [2] cb 45 [2] f6 }

  condition:
    any of them
}