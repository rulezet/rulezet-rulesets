rule TTP_XOR_MULT_DOSStub_4776 {
  strings:
    $key_4776 = { 13 1e [2] 67 06 [2] 20 04 [2] 67 15 [2] 29 19 [2] 25 13 [2] 32 18 [2] 29 56 [2] 14 }

  condition:
    any of them
}