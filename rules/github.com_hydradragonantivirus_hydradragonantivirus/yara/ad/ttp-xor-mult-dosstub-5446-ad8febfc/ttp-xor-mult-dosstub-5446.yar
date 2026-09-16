rule TTP_XOR_MULT_DOSStub_5446 {
  strings:
    $key_5446 = { 00 2e [2] 74 36 [2] 33 34 [2] 74 25 [2] 3a 29 [2] 36 23 [2] 21 28 [2] 3a 66 [2] 07 }

  condition:
    any of them
}