rule TTP_XOR_MULT_DOSStub_7571 {
  strings:
    $key_7571 = { 21 19 [2] 55 01 [2] 12 03 [2] 55 12 [2] 1b 1e [2] 17 14 [2] 00 1f [2] 1b 51 [2] 26 }

  condition:
    any of them
}