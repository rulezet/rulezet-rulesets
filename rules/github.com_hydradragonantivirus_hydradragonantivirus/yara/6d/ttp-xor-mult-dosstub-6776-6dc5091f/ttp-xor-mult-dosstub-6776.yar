rule TTP_XOR_MULT_DOSStub_6776 {
  strings:
    $key_6776 = { 33 1e [2] 47 06 [2] 00 04 [2] 47 15 [2] 09 19 [2] 05 13 [2] 12 18 [2] 09 56 [2] 34 }

  condition:
    any of them
}