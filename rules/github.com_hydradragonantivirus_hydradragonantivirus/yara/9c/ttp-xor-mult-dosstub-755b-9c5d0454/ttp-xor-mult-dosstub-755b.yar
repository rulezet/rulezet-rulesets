rule TTP_XOR_MULT_DOSStub_755b {
  strings:
    $key_755b = { 21 33 [2] 55 2b [2] 12 29 [2] 55 38 [2] 1b 34 [2] 17 3e [2] 00 35 [2] 1b 7b [2] 26 }

  condition:
    any of them
}