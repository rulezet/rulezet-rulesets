rule TTP_XOR_MULT_DOSStub_b37d {
  strings:
    $key_b37d = { e7 15 [2] 93 0d [2] d4 0f [2] 93 1e [2] dd 12 [2] d1 18 [2] c6 13 [2] dd 5d [2] e0 }

  condition:
    any of them
}