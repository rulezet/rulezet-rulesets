rule TTP_XOR_MULT_DOSStub_5400 {
  strings:
    $key_5400 = { 00 68 [2] 74 70 [2] 33 72 [2] 74 63 [2] 3a 6f [2] 36 65 [2] 21 6e [2] 3a 20 [2] 07 }

  condition:
    any of them
}