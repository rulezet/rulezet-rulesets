rule TTP_XOR_MULT_DOSStub_7776 {
  strings:
    $key_7776 = { 23 1e [2] 57 06 [2] 10 04 [2] 57 15 [2] 19 19 [2] 15 13 [2] 02 18 [2] 19 56 [2] 24 }

  condition:
    any of them
}