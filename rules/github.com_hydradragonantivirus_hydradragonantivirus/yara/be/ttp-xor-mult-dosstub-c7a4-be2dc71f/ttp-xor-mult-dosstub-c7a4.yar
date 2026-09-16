rule TTP_XOR_MULT_DOSStub_c7a4 {
  strings:
    $key_c7a4 = { 93 cc [2] e7 d4 [2] a0 d6 [2] e7 c7 [2] a9 cb [2] a5 c1 [2] b2 ca [2] a9 84 [2] 94 }

  condition:
    any of them
}