rule TTP_XOR_MULT_DOSStub_b34d {
  strings:
    $key_b34d = { e7 25 [2] 93 3d [2] d4 3f [2] 93 2e [2] dd 22 [2] d1 28 [2] c6 23 [2] dd 6d [2] e0 }

  condition:
    any of them
}