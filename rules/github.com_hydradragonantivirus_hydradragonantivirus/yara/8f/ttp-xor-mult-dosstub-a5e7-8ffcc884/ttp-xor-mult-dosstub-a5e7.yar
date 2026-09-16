rule TTP_XOR_MULT_DOSStub_a5e7 {
  strings:
    $key_a5e7 = { f1 8f [2] 85 97 [2] c2 95 [2] 85 84 [2] cb 88 [2] c7 82 [2] d0 89 [2] cb c7 [2] f6 }

  condition:
    any of them
}