rule TTP_XOR_MULT_DOSStub_40f6 {
  strings:
    $key_40f6 = { 14 9e [2] 60 86 [2] 27 84 [2] 60 95 [2] 2e 99 [2] 22 93 [2] 35 98 [2] 2e d6 [2] 13 }

  condition:
    any of them
}