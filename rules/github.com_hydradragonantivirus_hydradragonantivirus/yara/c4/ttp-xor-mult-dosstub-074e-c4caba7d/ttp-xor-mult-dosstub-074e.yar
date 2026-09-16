rule TTP_XOR_MULT_DOSStub_074e {
  strings:
    $key_074e = { 53 26 [2] 27 3e [2] 60 3c [2] 27 2d [2] 69 21 [2] 65 2b [2] 72 20 [2] 69 6e [2] 54 }

  condition:
    any of them
}