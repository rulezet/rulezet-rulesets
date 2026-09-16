rule TTP_XOR_MULT_DOSStub_a521 {
  strings:
    $key_a521 = { f1 49 [2] 85 51 [2] c2 53 [2] 85 42 [2] cb 4e [2] c7 44 [2] d0 4f [2] cb 01 [2] f6 }

  condition:
    any of them
}