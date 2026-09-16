rule TTP_XOR_MULT_DOSStub_b37e {
  strings:
    $key_b37e = { e7 16 [2] 93 0e [2] d4 0c [2] 93 1d [2] dd 11 [2] d1 1b [2] c6 10 [2] dd 5e [2] e0 }

  condition:
    any of them
}