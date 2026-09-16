rule TTP_XOR_MULT_DOSStub_a503 {
  strings:
    $key_a503 = { f1 6b [2] 85 73 [2] c2 71 [2] 85 60 [2] cb 6c [2] c7 66 [2] d0 6d [2] cb 23 [2] f6 }

  condition:
    any of them
}