rule TTP_XOR_MULT_DOSStub_751e {
  strings:
    $key_751e = { 21 76 [2] 55 6e [2] 12 6c [2] 55 7d [2] 1b 71 [2] 17 7b [2] 00 70 [2] 1b 3e [2] 26 }

  condition:
    any of them
}