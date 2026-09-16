rule TTP_XOR_MULT_DOSStub_a516 {
  strings:
    $key_a516 = { f1 7e [2] 85 66 [2] c2 64 [2] 85 75 [2] cb 79 [2] c7 73 [2] d0 78 [2] cb 36 [2] f6 }

  condition:
    any of them
}