rule TTP_XOR_MULT_DOSStub_1070 {
  strings:
    $key_1070 = { 44 18 [2] 30 00 [2] 77 02 [2] 30 13 [2] 7e 1f [2] 72 15 [2] 65 1e [2] 7e 50 [2] 43 }

  condition:
    any of them
}