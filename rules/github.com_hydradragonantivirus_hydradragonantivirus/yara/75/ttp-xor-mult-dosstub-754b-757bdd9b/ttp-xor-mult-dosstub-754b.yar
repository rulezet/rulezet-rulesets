rule TTP_XOR_MULT_DOSStub_754b {
  strings:
    $key_754b = { 21 23 [2] 55 3b [2] 12 39 [2] 55 28 [2] 1b 24 [2] 17 2e [2] 00 25 [2] 1b 6b [2] 26 }

  condition:
    any of them
}