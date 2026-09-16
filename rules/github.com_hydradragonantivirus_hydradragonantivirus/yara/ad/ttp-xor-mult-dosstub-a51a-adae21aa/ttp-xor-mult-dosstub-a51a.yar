rule TTP_XOR_MULT_DOSStub_a51a {
  strings:
    $key_a51a = { f1 72 [2] 85 6a [2] c2 68 [2] 85 79 [2] cb 75 [2] c7 7f [2] d0 74 [2] cb 3a [2] f6 }

  condition:
    any of them
}