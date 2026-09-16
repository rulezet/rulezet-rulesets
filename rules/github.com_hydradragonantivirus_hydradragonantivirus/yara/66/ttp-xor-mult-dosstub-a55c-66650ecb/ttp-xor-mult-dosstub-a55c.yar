rule TTP_XOR_MULT_DOSStub_a55c {
  strings:
    $key_a55c = { f1 34 [2] 85 2c [2] c2 2e [2] 85 3f [2] cb 33 [2] c7 39 [2] d0 32 [2] cb 7c [2] f6 }

  condition:
    any of them
}