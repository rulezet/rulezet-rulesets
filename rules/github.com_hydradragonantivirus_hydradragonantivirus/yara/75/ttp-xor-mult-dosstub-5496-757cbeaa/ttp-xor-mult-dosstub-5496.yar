rule TTP_XOR_MULT_DOSStub_5496 {
  strings:
    $key_5496 = { 00 fe [2] 74 e6 [2] 33 e4 [2] 74 f5 [2] 3a f9 [2] 36 f3 [2] 21 f8 [2] 3a b6 [2] 07 }

  condition:
    any of them
}