rule TTP_XOR_MULT_DOSStub_a5b3 {
  strings:
    $key_a5b3 = { f1 db [2] 85 c3 [2] c2 c1 [2] 85 d0 [2] cb dc [2] c7 d6 [2] d0 dd [2] cb 93 [2] f6 }

  condition:
    any of them
}