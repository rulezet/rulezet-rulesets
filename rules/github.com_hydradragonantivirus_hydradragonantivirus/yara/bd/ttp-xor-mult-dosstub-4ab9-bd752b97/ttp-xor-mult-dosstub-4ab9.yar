rule TTP_XOR_MULT_DOSStub_4ab9 {
  strings:
    $key_4ab9 = { 1e d1 [2] 6a c9 [2] 2d cb [2] 6a da [2] 24 d6 [2] 28 dc [2] 3f d7 [2] 24 99 [2] 19 }

  condition:
    any of them
}