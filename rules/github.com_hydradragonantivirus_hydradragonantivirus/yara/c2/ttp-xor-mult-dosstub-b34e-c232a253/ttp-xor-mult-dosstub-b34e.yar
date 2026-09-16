rule TTP_XOR_MULT_DOSStub_b34e {
  strings:
    $key_b34e = { e7 26 [2] 93 3e [2] d4 3c [2] 93 2d [2] dd 21 [2] d1 2b [2] c6 20 [2] dd 6e [2] e0 }

  condition:
    any of them
}