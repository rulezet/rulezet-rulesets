rule TTP_XOR_MULT_DOSStub_a55b {
  strings:
    $key_a55b = { f1 33 [2] 85 2b [2] c2 29 [2] 85 38 [2] cb 34 [2] c7 3e [2] d0 35 [2] cb 7b [2] f6 }

  condition:
    any of them
}