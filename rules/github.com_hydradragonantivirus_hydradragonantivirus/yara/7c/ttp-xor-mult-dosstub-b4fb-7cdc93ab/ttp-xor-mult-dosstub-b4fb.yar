rule TTP_XOR_MULT_DOSStub_b4fb {
  strings:
    $key_b4fb = { e0 93 [2] 94 8b [2] d3 89 [2] 94 98 [2] da 94 [2] d6 9e [2] c1 95 [2] da db [2] e7 }

  condition:
    any of them
}