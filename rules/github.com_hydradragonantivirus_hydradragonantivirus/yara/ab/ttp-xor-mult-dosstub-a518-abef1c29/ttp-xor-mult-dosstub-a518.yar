rule TTP_XOR_MULT_DOSStub_a518 {
  strings:
    $key_a518 = { f1 70 [2] 85 68 [2] c2 6a [2] 85 7b [2] cb 77 [2] c7 7d [2] d0 76 [2] cb 38 [2] f6 }

  condition:
    any of them
}