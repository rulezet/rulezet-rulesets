rule TTP_XOR_MULT_DOSStub_044e {
  strings:
    $key_044e = { 50 26 [2] 24 3e [2] 63 3c [2] 24 2d [2] 6a 21 [2] 66 2b [2] 71 20 [2] 6a 6e [2] 57 }

  condition:
    any of them
}