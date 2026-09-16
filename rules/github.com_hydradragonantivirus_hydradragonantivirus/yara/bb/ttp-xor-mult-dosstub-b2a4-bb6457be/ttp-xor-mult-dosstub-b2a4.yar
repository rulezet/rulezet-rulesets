rule TTP_XOR_MULT_DOSStub_b2a4 {
  strings:
    $key_b2a4 = { e6 cc [2] 92 d4 [2] d5 d6 [2] 92 c7 [2] dc cb [2] d0 c1 [2] c7 ca [2] dc 84 [2] e1 }

  condition:
    any of them
}