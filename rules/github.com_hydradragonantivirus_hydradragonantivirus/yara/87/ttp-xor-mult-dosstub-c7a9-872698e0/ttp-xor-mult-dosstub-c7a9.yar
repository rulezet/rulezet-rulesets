rule TTP_XOR_MULT_DOSStub_c7a9 {
  strings:
    $key_c7a9 = { 93 c1 [2] e7 d9 [2] a0 db [2] e7 ca [2] a9 c6 [2] a5 cc [2] b2 c7 [2] a9 89 [2] 94 }

  condition:
    any of them
}