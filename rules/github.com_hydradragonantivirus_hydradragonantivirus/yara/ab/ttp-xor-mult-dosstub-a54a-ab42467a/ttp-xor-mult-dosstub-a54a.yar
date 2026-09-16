rule TTP_XOR_MULT_DOSStub_a54a {
  strings:
    $key_a54a = { f1 22 [2] 85 3a [2] c2 38 [2] 85 29 [2] cb 25 [2] c7 2f [2] d0 24 [2] cb 6a [2] f6 }

  condition:
    any of them
}