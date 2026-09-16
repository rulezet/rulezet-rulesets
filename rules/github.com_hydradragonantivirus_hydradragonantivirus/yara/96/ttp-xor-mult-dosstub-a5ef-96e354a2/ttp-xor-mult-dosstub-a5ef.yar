rule TTP_XOR_MULT_DOSStub_a5ef {
  strings:
    $key_a5ef = { f1 87 [2] 85 9f [2] c2 9d [2] 85 8c [2] cb 80 [2] c7 8a [2] d0 81 [2] cb cf [2] f6 }

  condition:
    any of them
}