rule TTP_XOR_MULT_DOSStub_a4a4 {
  strings:
    $key_a4a4 = { f0 cc [2] 84 d4 [2] c3 d6 [2] 84 c7 [2] ca cb [2] c6 c1 [2] d1 ca [2] ca 84 [2] f7 }

  condition:
    any of them
}