rule TTP_XOR_MULT_DOSStub_7536 {
  strings:
    $key_7536 = { 21 5e [2] 55 46 [2] 12 44 [2] 55 55 [2] 1b 59 [2] 17 53 [2] 00 58 [2] 1b 16 [2] 26 }

  condition:
    any of them
}