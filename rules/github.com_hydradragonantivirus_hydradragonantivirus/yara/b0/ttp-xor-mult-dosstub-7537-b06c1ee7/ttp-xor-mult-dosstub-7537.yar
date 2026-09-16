rule TTP_XOR_MULT_DOSStub_7537 {
  strings:
    $key_7537 = { 21 5f [2] 55 47 [2] 12 45 [2] 55 54 [2] 1b 58 [2] 17 52 [2] 00 59 [2] 1b 17 [2] 26 }

  condition:
    any of them
}