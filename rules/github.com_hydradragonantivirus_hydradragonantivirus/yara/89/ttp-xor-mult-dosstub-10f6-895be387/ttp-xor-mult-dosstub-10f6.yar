rule TTP_XOR_MULT_DOSStub_10f6 {
  strings:
    $key_10f6 = { 44 9e [2] 30 86 [2] 77 84 [2] 30 95 [2] 7e 99 [2] 72 93 [2] 65 98 [2] 7e d6 [2] 43 }

  condition:
    any of them
}