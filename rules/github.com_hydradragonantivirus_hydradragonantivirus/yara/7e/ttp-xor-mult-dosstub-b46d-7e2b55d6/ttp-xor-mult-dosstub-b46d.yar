rule TTP_XOR_MULT_DOSStub_b46d {
  strings:
    $key_b46d = { e0 05 [2] 94 1d [2] d3 1f [2] 94 0e [2] da 02 [2] d6 08 [2] c1 03 [2] da 4d [2] e7 }

  condition:
    any of them
}