rule TTP_XOR_MULT_DOSStub_b31d {
  strings:
    $key_b31d = { e7 75 [2] 93 6d [2] d4 6f [2] 93 7e [2] dd 72 [2] d1 78 [2] c6 73 [2] dd 3d [2] e0 }

  condition:
    any of them
}