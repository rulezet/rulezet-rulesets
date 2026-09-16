rule TTP_XOR_MULT_DOSStub_b41b {
  strings:
    $key_b41b = { e0 73 [2] 94 6b [2] d3 69 [2] 94 78 [2] da 74 [2] d6 7e [2] c1 75 [2] da 3b [2] e7 }

  condition:
    any of them
}