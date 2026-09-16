rule TTP_XOR_MULT_DOSStub_5ab9 {
  strings:
    $key_5ab9 = { 0e d1 [2] 7a c9 [2] 3d cb [2] 7a da [2] 34 d6 [2] 38 dc [2] 2f d7 [2] 34 99 [2] 09 }

  condition:
    any of them
}