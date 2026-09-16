rule TTP_XOR_MULT_DOSStub_434e {
  strings:
    $key_434e = { 17 26 [2] 63 3e [2] 24 3c [2] 63 2d [2] 2d 21 [2] 21 2b [2] 36 20 [2] 2d 6e [2] 10 }

  condition:
    any of them
}