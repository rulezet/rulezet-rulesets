rule TTP_XOR_MULT_DOSStub_b4e1 {
  strings:
    $key_b4e1 = { e0 89 [2] 94 91 [2] d3 93 [2] 94 82 [2] da 8e [2] d6 84 [2] c1 8f [2] da c1 [2] e7 }

  condition:
    any of them
}