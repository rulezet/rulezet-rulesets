rule TTP_XOR_MULT_DOSStub_7506 {
  strings:
    $key_7506 = { 21 6e [2] 55 76 [2] 12 74 [2] 55 65 [2] 1b 69 [2] 17 63 [2] 00 68 [2] 1b 26 [2] 26 }

  condition:
    any of them
}