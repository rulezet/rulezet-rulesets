rule TTP_XOR_MULT_DOSStub_b4a4 {
  strings:
    $key_b4a4 = { e0 cc [2] 94 d4 [2] d3 d6 [2] 94 c7 [2] da cb [2] d6 c1 [2] c1 ca [2] da 84 [2] e7 }

  condition:
    any of them
}