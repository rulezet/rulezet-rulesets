rule TTP_XOR_MULT_DOSStub_b451 {
  strings:
    $key_b451 = { e0 39 [2] 94 21 [2] d3 23 [2] 94 32 [2] da 3e [2] d6 34 [2] c1 3f [2] da 71 [2] e7 }

  condition:
    any of them
}