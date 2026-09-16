rule TTP_XOR_MULT_DOSStub_b44d {
  strings:
    $key_b44d = { e0 25 [2] 94 3d [2] d3 3f [2] 94 2e [2] da 22 [2] d6 28 [2] c1 23 [2] da 6d [2] e7 }

  condition:
    any of them
}