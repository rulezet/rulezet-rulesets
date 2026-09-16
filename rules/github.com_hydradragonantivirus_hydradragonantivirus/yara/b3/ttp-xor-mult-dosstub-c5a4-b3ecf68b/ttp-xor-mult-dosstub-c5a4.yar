rule TTP_XOR_MULT_DOSStub_c5a4 {
  strings:
    $key_c5a4 = { 91 cc [2] e5 d4 [2] a2 d6 [2] e5 c7 [2] ab cb [2] a7 c1 [2] b0 ca [2] ab 84 [2] 96 }

  condition:
    any of them
}