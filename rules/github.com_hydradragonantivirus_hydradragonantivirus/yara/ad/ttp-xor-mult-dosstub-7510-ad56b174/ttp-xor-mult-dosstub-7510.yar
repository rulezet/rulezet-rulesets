rule TTP_XOR_MULT_DOSStub_7510 {
  strings:
    $key_7510 = { 21 78 [2] 55 60 [2] 12 62 [2] 55 73 [2] 1b 7f [2] 17 75 [2] 00 7e [2] 1b 30 [2] 26 }

  condition:
    any of them
}