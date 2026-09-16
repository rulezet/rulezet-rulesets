rule TTP_XOR_MULT_DOSStub_b4f5 {
  strings:
    $key_b4f5 = { e0 9d [2] 94 85 [2] d3 87 [2] 94 96 [2] da 9a [2] d6 90 [2] c1 9b [2] da d5 [2] e7 }

  condition:
    any of them
}