rule TTP_XOR_MULT_DOSStub_b46e {
  strings:
    $key_b46e = { e0 06 [2] 94 1e [2] d3 1c [2] 94 0d [2] da 01 [2] d6 0b [2] c1 00 [2] da 4e [2] e7 }

  condition:
    any of them
}