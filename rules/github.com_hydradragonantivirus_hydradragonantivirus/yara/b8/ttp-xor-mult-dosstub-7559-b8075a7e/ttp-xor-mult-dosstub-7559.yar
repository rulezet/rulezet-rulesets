rule TTP_XOR_MULT_DOSStub_7559 {
  strings:
    $key_7559 = { 21 31 [2] 55 29 [2] 12 2b [2] 55 3a [2] 1b 36 [2] 17 3c [2] 00 37 [2] 1b 79 [2] 26 }

  condition:
    any of them
}