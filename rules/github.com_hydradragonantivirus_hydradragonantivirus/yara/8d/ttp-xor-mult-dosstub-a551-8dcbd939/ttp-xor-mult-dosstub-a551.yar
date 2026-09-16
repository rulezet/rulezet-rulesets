rule TTP_XOR_MULT_DOSStub_a551 {
  strings:
    $key_a551 = { f1 39 [2] 85 21 [2] c2 23 [2] 85 32 [2] cb 3e [2] c7 34 [2] d0 3f [2] cb 71 [2] f6 }

  condition:
    any of them
}