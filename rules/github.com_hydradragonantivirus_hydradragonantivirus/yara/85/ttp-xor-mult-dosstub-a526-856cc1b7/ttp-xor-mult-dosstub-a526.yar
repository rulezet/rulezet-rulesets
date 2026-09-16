rule TTP_XOR_MULT_DOSStub_a526 {
  strings:
    $key_a526 = { f1 4e [2] 85 56 [2] c2 54 [2] 85 45 [2] cb 49 [2] c7 43 [2] d0 48 [2] cb 06 [2] f6 }

  condition:
    any of them
}