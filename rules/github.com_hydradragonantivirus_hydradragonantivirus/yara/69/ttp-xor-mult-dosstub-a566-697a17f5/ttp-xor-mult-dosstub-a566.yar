rule TTP_XOR_MULT_DOSStub_a566 {
  strings:
    $key_a566 = { f1 0e [2] 85 16 [2] c2 14 [2] 85 05 [2] cb 09 [2] c7 03 [2] d0 08 [2] cb 46 [2] f6 }

  condition:
    any of them
}