rule TTP_XOR_MULT_DOSStub_a5b8 {
  strings:
    $key_a5b8 = { f1 d0 [2] 85 c8 [2] c2 ca [2] 85 db [2] cb d7 [2] c7 dd [2] d0 d6 [2] cb 98 [2] f6 }

  condition:
    any of them
}