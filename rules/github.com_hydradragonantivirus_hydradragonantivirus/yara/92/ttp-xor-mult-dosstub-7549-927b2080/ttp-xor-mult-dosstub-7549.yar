rule TTP_XOR_MULT_DOSStub_7549 {
  strings:
    $key_7549 = { 21 21 [2] 55 39 [2] 12 3b [2] 55 2a [2] 1b 26 [2] 17 2c [2] 00 27 [2] 1b 69 [2] 26 }

  condition:
    any of them
}