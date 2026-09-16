rule TTP_XOR_MULT_DOSStub_7550 {
  strings:
    $key_7550 = { 21 38 [2] 55 20 [2] 12 22 [2] 55 33 [2] 1b 3f [2] 17 35 [2] 00 3e [2] 1b 70 [2] 26 }

  condition:
    any of them
}