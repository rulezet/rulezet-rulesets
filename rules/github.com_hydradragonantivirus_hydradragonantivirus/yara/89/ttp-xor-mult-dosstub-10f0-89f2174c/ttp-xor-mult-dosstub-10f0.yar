rule TTP_XOR_MULT_DOSStub_10f0 {
  strings:
    $key_10f0 = { 44 98 [2] 30 80 [2] 77 82 [2] 30 93 [2] 7e 9f [2] 72 95 [2] 65 9e [2] 7e d0 [2] 43 }

  condition:
    any of them
}