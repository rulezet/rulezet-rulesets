rule TTP_XOR_MULT_DOSStub_1ab9 {
  strings:
    $key_1ab9 = { 4e d1 [2] 3a c9 [2] 7d cb [2] 3a da [2] 74 d6 [2] 78 dc [2] 6f d7 [2] 74 99 [2] 49 }

  condition:
    any of them
}