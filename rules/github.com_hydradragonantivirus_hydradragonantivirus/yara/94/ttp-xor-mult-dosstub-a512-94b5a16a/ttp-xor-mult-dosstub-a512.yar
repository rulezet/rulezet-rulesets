rule TTP_XOR_MULT_DOSStub_a512 {
  strings:
    $key_a512 = { f1 7a [2] 85 62 [2] c2 60 [2] 85 71 [2] cb 7d [2] c7 77 [2] d0 7c [2] cb 32 [2] f6 }

  condition:
    any of them
}