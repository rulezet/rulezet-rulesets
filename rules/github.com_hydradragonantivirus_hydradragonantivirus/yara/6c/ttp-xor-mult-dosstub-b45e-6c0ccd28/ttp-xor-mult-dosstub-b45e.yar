rule TTP_XOR_MULT_DOSStub_b45e {
  strings:
    $key_b45e = { e0 36 [2] 94 2e [2] d3 2c [2] 94 3d [2] da 31 [2] d6 3b [2] c1 30 [2] da 7e [2] e7 }

  condition:
    any of them
}