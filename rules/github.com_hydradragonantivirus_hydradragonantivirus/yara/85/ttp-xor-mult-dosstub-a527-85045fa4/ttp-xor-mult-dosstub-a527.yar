rule TTP_XOR_MULT_DOSStub_a527 {
  strings:
    $key_a527 = { f1 4f [2] 85 57 [2] c2 55 [2] 85 44 [2] cb 48 [2] c7 42 [2] d0 49 [2] cb 07 [2] f6 }

  condition:
    any of them
}