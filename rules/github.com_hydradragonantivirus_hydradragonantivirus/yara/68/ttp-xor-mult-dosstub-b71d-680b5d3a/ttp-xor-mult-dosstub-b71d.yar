rule TTP_XOR_MULT_DOSStub_b71d {
  strings:
    $key_b71d = { e3 75 [2] 97 6d [2] d0 6f [2] 97 7e [2] d9 72 [2] d5 78 [2] c2 73 [2] d9 3d [2] e4 }

  condition:
    any of them
}