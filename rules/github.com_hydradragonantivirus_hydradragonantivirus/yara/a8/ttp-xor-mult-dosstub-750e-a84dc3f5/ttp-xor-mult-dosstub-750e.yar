rule TTP_XOR_MULT_DOSStub_750e {
  strings:
    $key_750e = { 21 66 [2] 55 7e [2] 12 7c [2] 55 6d [2] 1b 61 [2] 17 6b [2] 00 60 [2] 1b 2e [2] 26 }

  condition:
    any of them
}