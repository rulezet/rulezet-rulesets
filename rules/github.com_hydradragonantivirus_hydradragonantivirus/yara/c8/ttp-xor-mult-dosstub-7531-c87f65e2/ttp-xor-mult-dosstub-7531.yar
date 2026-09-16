rule TTP_XOR_MULT_DOSStub_7531 {
  strings:
    $key_7531 = { 21 59 [2] 55 41 [2] 12 43 [2] 55 52 [2] 1b 5e [2] 17 54 [2] 00 5f [2] 1b 11 [2] 26 }

  condition:
    any of them
}