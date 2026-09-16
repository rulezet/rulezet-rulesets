rule TTP_XOR_MULT_DOSStub_2ab9 {
  strings:
    $key_2ab9 = { 7e d1 [2] 0a c9 [2] 4d cb [2] 0a da [2] 44 d6 [2] 48 dc [2] 5f d7 [2] 44 99 [2] 79 }

  condition:
    any of them
}