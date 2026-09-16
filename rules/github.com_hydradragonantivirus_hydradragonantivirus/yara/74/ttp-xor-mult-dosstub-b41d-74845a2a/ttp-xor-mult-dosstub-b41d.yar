rule TTP_XOR_MULT_DOSStub_b41d {
  strings:
    $key_b41d = { e0 75 [2] 94 6d [2] d3 6f [2] 94 7e [2] da 72 [2] d6 78 [2] c1 73 [2] da 3d [2] e7 }

  condition:
    any of them
}