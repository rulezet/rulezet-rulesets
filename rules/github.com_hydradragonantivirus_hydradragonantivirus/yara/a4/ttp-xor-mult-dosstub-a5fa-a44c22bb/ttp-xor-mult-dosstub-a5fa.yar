rule TTP_XOR_MULT_DOSStub_a5fa {
  strings:
    $key_a5fa = { f1 92 [2] 85 8a [2] c2 88 [2] 85 99 [2] cb 95 [2] c7 9f [2] d0 94 [2] cb da [2] f6 }

  condition:
    any of them
}