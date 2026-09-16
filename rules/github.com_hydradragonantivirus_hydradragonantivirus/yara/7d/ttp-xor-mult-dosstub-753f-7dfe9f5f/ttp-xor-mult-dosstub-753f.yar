rule TTP_XOR_MULT_DOSStub_753f {
  strings:
    $key_753f = { 21 57 [2] 55 4f [2] 12 4d [2] 55 5c [2] 1b 50 [2] 17 5a [2] 00 51 [2] 1b 1f [2] 26 }

  condition:
    any of them
}