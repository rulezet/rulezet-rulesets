rule TTP_XOR_MULT_DOSStub_b43e {
  strings:
    $key_b43e = { e0 56 [2] 94 4e [2] d3 4c [2] 94 5d [2] da 51 [2] d6 5b [2] c1 50 [2] da 1e [2] e7 }

  condition:
    any of them
}