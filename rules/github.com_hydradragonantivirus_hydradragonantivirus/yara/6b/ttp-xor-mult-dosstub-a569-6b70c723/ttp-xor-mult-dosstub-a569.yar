rule TTP_XOR_MULT_DOSStub_a569 {
  strings:
    $key_a569 = { f1 01 [2] 85 19 [2] c2 1b [2] 85 0a [2] cb 06 [2] c7 0c [2] d0 07 [2] cb 49 [2] f6 }

  condition:
    any of them
}