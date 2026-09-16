rule TTP_XOR_MULT_DOSStub_755a {
  strings:
    $key_755a = { 21 32 [2] 55 2a [2] 12 28 [2] 55 39 [2] 1b 35 [2] 17 3f [2] 00 34 [2] 1b 7a [2] 26 }

  condition:
    any of them
}