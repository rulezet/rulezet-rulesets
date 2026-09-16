rule TTP_XOR_MULT_DOSStub_7546 {
  strings:
    $key_7546 = { 21 2e [2] 55 36 [2] 12 34 [2] 55 25 [2] 1b 29 [2] 17 23 [2] 00 28 [2] 1b 66 [2] 26 }

  condition:
    any of them
}