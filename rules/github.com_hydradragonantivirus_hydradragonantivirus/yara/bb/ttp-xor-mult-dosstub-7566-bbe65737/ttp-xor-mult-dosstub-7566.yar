rule TTP_XOR_MULT_DOSStub_7566 {
  strings:
    $key_7566 = { 21 0e [2] 55 16 [2] 12 14 [2] 55 05 [2] 1b 09 [2] 17 03 [2] 00 08 [2] 1b 46 [2] 26 }

  condition:
    any of them
}