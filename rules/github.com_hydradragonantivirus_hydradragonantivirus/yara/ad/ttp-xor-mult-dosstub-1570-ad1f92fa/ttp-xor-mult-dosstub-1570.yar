rule TTP_XOR_MULT_DOSStub_1570 {
  strings:
    $key_1570 = { 41 18 [2] 35 00 [2] 72 02 [2] 35 13 [2] 7b 1f [2] 77 15 [2] 60 1e [2] 7b 50 [2] 46 }

  condition:
    any of them
}