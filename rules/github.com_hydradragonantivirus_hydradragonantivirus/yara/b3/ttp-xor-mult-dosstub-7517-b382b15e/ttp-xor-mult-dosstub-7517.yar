rule TTP_XOR_MULT_DOSStub_7517 {
  strings:
    $key_7517 = { 21 7f [2] 55 67 [2] 12 65 [2] 55 74 [2] 1b 78 [2] 17 72 [2] 00 79 [2] 1b 37 [2] 26 }

  condition:
    any of them
}