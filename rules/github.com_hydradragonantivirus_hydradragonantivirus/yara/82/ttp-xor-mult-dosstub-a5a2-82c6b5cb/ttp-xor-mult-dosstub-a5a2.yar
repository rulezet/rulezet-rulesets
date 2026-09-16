rule TTP_XOR_MULT_DOSStub_a5a2 {
  strings:
    $key_a5a2 = { f1 ca [2] 85 d2 [2] c2 d0 [2] 85 c1 [2] cb cd [2] c7 c7 [2] d0 cc [2] cb 82 [2] f6 }

  condition:
    any of them
}