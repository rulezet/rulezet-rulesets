rule TTP_XOR_MULT_DOSStub_b07e {
  strings:
    $key_b07e = { e4 16 [2] 90 0e [2] d7 0c [2] 90 1d [2] de 11 [2] d2 1b [2] c5 10 [2] de 5e [2] e3 }

  condition:
    any of them
}