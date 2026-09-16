rule TTP_XOR_MULT_DOSStub_a519 {
  strings:
    $key_a519 = { f1 71 [2] 85 69 [2] c2 6b [2] 85 7a [2] cb 76 [2] c7 7c [2] d0 77 [2] cb 39 [2] f6 }

  condition:
    any of them
}