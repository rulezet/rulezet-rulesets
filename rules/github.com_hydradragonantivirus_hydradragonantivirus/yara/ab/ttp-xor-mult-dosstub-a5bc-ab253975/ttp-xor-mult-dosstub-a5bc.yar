rule TTP_XOR_MULT_DOSStub_a5bc {
  strings:
    $key_a5bc = { f1 d4 [2] 85 cc [2] c2 ce [2] 85 df [2] cb d3 [2] c7 d9 [2] d0 d2 [2] cb 9c [2] f6 }

  condition:
    any of them
}