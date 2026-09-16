rule TTP_XOR_MULT_DOSStub_a5f7 {
  strings:
    $key_a5f7 = { f1 9f [2] 85 87 [2] c2 85 [2] 85 94 [2] cb 98 [2] c7 92 [2] d0 99 [2] cb d7 [2] f6 }

  condition:
    any of them
}