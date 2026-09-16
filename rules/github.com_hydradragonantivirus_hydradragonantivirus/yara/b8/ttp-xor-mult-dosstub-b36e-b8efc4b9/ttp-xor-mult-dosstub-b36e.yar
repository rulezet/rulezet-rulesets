rule TTP_XOR_MULT_DOSStub_b36e {
  strings:
    $key_b36e = { e7 06 [2] 93 1e [2] d4 1c [2] 93 0d [2] dd 01 [2] d1 0b [2] c6 00 [2] dd 4e [2] e0 }

  condition:
    any of them
}