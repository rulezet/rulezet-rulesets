rule TTP_XOR_MULT_DOSStub_a538 {
  strings:
    $key_a538 = { f1 50 [2] 85 48 [2] c2 4a [2] 85 5b [2] cb 57 [2] c7 5d [2] d0 56 [2] cb 18 [2] f6 }

  condition:
    any of them
}