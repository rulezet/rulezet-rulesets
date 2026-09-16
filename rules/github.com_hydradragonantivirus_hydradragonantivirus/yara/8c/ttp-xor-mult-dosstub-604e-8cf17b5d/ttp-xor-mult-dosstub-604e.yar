rule TTP_XOR_MULT_DOSStub_604e {
  strings:
    $key_604e = { 34 26 [2] 40 3e [2] 07 3c [2] 40 2d [2] 0e 21 [2] 02 2b [2] 15 20 [2] 0e 6e [2] 33 }

  condition:
    any of them
}