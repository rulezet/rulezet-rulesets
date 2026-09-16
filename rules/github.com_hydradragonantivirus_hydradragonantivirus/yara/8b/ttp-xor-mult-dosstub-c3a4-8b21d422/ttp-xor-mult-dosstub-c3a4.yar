rule TTP_XOR_MULT_DOSStub_c3a4 {
  strings:
    $key_c3a4 = { 97 cc [2] e3 d4 [2] a4 d6 [2] e3 c7 [2] ad cb [2] a1 c1 [2] b6 ca [2] ad 84 [2] 90 }

  condition:
    any of them
}