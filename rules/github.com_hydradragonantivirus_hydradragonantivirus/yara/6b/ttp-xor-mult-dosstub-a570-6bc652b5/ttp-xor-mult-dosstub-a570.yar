rule TTP_XOR_MULT_DOSStub_a570 {
  strings:
    $key_a570 = { f1 18 [2] 85 00 [2] c2 02 [2] 85 13 [2] cb 1f [2] c7 15 [2] d0 1e [2] cb 50 [2] f6 }

  condition:
    any of them
}