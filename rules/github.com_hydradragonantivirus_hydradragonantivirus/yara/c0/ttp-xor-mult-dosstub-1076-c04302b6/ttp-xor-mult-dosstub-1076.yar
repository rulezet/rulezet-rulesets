rule TTP_XOR_MULT_DOSStub_1076 {
  strings:
    $key_1076 = { 44 1e [2] 30 06 [2] 77 04 [2] 30 15 [2] 7e 19 [2] 72 13 [2] 65 18 [2] 7e 56 [2] 43 }

  condition:
    any of them
}