rule TTP_XOR_MULT_DOSStub_374e {
  strings:
    $key_374e = { 63 26 [2] 17 3e [2] 50 3c [2] 17 2d [2] 59 21 [2] 55 2b [2] 42 20 [2] 59 6e [2] 64 }

  condition:
    any of them
}