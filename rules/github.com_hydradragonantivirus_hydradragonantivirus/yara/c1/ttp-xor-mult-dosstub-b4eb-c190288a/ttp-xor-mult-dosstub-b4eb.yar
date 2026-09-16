rule TTP_XOR_MULT_DOSStub_b4eb {
  strings:
    $key_b4eb = { e0 83 [2] 94 9b [2] d3 99 [2] 94 88 [2] da 84 [2] d6 8e [2] c1 85 [2] da cb [2] e7 }

  condition:
    any of them
}