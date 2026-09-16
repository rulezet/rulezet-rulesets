rule TTP_XOR_MULT_DOSStub_a5a4 {
  strings:
    $key_a5a4 = { f1 cc [2] 85 d4 [2] c2 d6 [2] 85 c7 [2] cb cb [2] c7 c1 [2] d0 ca [2] cb 84 [2] f6 }

  condition:
    any of them
}