rule TTP_XOR_MULT_DOSStub_454e {
  strings:
    $key_454e = { 11 26 [2] 65 3e [2] 22 3c [2] 65 2d [2] 2b 21 [2] 27 2b [2] 30 20 [2] 2b 6e [2] 16 }

  condition:
    any of them
}