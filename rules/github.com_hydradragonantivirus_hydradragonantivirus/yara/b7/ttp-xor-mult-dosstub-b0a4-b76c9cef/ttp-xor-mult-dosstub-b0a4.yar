rule TTP_XOR_MULT_DOSStub_b0a4 {
  strings:
    $key_b0a4 = { e4 cc [2] 90 d4 [2] d7 d6 [2] 90 c7 [2] de cb [2] d2 c1 [2] c5 ca [2] de 84 [2] e3 }

  condition:
    any of them
}