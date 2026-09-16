rule TTP_XOR_MULT_DOSStub_755c {
  strings:
    $key_755c = { 21 34 [2] 55 2c [2] 12 2e [2] 55 3f [2] 1b 33 [2] 17 39 [2] 00 32 [2] 1b 7c [2] 26 }

  condition:
    any of them
}