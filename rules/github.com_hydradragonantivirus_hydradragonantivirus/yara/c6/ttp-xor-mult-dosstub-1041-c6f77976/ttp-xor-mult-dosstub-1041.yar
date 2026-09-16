rule TTP_XOR_MULT_DOSStub_1041 {
  strings:
    $key_1041 = { 44 29 [2] 30 31 [2] 77 33 [2] 30 22 [2] 7e 2e [2] 72 24 [2] 65 2f [2] 7e 61 [2] 43 }

  condition:
    any of them
}