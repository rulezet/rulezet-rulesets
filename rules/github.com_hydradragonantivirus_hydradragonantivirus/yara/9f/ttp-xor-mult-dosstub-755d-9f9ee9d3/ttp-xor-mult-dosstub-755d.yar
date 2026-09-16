rule TTP_XOR_MULT_DOSStub_755d {
  strings:
    $key_755d = { 21 35 [2] 55 2d [2] 12 2f [2] 55 3e [2] 1b 32 [2] 17 38 [2] 00 33 [2] 1b 7d [2] 26 }

  condition:
    any of them
}