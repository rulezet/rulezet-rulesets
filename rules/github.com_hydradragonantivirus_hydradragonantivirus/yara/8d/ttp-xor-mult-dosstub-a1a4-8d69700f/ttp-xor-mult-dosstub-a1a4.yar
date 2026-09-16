rule TTP_XOR_MULT_DOSStub_a1a4 {
  strings:
    $key_a1a4 = { f5 cc [2] 81 d4 [2] c6 d6 [2] 81 c7 [2] cf cb [2] c3 c1 [2] d4 ca [2] cf 84 [2] f2 }

  condition:
    any of them
}