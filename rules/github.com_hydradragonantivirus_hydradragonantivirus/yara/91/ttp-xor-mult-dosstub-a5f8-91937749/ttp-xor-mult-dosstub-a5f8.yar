rule TTP_XOR_MULT_DOSStub_a5f8 {
  strings:
    $key_a5f8 = { f1 90 [2] 85 88 [2] c2 8a [2] 85 9b [2] cb 97 [2] c7 9d [2] d0 96 [2] cb d8 [2] f6 }

  condition:
    any of them
}