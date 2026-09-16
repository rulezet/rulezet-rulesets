rule TTP_XOR_MULT_DOSStub_a550 {
  strings:
    $key_a550 = { f1 38 [2] 85 20 [2] c2 22 [2] 85 33 [2] cb 3f [2] c7 35 [2] d0 3e [2] cb 70 [2] f6 }

  condition:
    any of them
}