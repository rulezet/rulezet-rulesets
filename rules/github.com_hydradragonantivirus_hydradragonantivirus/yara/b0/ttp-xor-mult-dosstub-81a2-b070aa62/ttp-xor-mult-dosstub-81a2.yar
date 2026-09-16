rule TTP_XOR_MULT_DOSStub_81a2 {
  strings:
    $key_81a2 = { d5 ca [2] a1 d2 [2] e6 d0 [2] a1 c1 [2] ef cd [2] e3 c7 [2] f4 cc [2] ef 82 [2] d2 }

  condition:
    any of them
}