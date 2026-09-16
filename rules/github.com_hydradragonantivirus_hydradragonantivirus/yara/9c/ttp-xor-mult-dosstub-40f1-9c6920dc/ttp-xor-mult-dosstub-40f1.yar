rule TTP_XOR_MULT_DOSStub_40f1 {
  strings:
    $key_40f1 = { 14 99 [2] 60 81 [2] 27 83 [2] 60 92 [2] 2e 9e [2] 22 94 [2] 35 9f [2] 2e d1 [2] 13 }

  condition:
    any of them
}