rule TTP_XOR_MULT_DOSStub_83a4 {
  strings:
    $key_83a4 = { d7 cc [2] a3 d4 [2] e4 d6 [2] a3 c7 [2] ed cb [2] e1 c1 [2] f6 ca [2] ed 84 [2] d0 }

  condition:
    any of them
}