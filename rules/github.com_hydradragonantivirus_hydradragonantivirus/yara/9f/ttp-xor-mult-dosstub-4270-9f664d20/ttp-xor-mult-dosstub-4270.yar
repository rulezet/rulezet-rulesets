rule TTP_XOR_MULT_DOSStub_4270 {
  strings:
    $key_4270 = { 16 18 [2] 62 00 [2] 25 02 [2] 62 13 [2] 2c 1f [2] 20 15 [2] 37 1e [2] 2c 50 [2] 11 }

  condition:
    any of them
}