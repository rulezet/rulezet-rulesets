rule TTP_XOR_MULT_DOSStub_a534 {
  strings:
    $key_a534 = { f1 5c [2] 85 44 [2] c2 46 [2] 85 57 [2] cb 5b [2] c7 51 [2] d0 5a [2] cb 14 [2] f6 }

  condition:
    any of them
}