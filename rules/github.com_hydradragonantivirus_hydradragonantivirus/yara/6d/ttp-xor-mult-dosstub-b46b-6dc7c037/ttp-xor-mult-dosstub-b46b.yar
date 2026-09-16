rule TTP_XOR_MULT_DOSStub_b46b {
  strings:
    $key_b46b = { e0 03 [2] 94 1b [2] d3 19 [2] 94 08 [2] da 04 [2] d6 0e [2] c1 05 [2] da 4b [2] e7 }

  condition:
    any of them
}