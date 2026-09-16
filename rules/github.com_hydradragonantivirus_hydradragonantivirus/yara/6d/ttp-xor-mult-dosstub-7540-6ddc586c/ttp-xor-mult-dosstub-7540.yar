rule TTP_XOR_MULT_DOSStub_7540 {
  strings:
    $key_7540 = { 21 28 [2] 55 30 [2] 12 32 [2] 55 23 [2] 1b 2f [2] 17 25 [2] 00 2e [2] 1b 60 [2] 26 }

  condition:
    any of them
}