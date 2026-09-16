rule TTP_XOR_MULT_DOSStub_c6a9 {
  strings:
    $key_c6a9 = { 92 c1 [2] e6 d9 [2] a1 db [2] e6 ca [2] a8 c6 [2] a4 cc [2] b3 c7 [2] a8 89 [2] 95 }

  condition:
    any of them
}