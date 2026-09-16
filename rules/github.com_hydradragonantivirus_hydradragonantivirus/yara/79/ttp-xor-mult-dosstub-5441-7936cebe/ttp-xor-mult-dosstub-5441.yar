rule TTP_XOR_MULT_DOSStub_5441 {
  strings:
    $key_5441 = { 00 29 [2] 74 31 [2] 33 33 [2] 74 22 [2] 3a 2e [2] 36 24 [2] 21 2f [2] 3a 61 [2] 07 }

  condition:
    any of them
}