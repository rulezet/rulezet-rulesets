rule TTP_XOR_MULT_DOSStub_b1e1 {
  strings:
    $key_b1e1 = { e5 89 [2] 91 91 [2] d6 93 [2] 91 82 [2] df 8e [2] d3 84 [2] c4 8f [2] df c1 [2] e2 }

  condition:
    any of them
}