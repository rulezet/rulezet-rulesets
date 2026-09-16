rule TTP_XOR_MULT_DOSStub_1576 {
  strings:
    $key_1576 = { 41 1e [2] 35 06 [2] 72 04 [2] 35 15 [2] 7b 19 [2] 77 13 [2] 60 18 [2] 7b 56 [2] 46 }

  condition:
    any of them
}