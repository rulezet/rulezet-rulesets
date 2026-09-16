rule TTP_XOR_MULT_DOSStub_3ab9 {
  strings:
    $key_3ab9 = { 6e d1 [2] 1a c9 [2] 5d cb [2] 1a da [2] 54 d6 [2] 58 dc [2] 4f d7 [2] 54 99 [2] 69 }

  condition:
    any of them
}