rule TTP_XOR_MULT_DOSStub_c780 {
  strings:
    $key_c780 = { 93 e8 [2] e7 f0 [2] a0 f2 [2] e7 e3 [2] a9 ef [2] a5 e5 [2] b2 ee [2] a9 a0 [2] 94 }

  condition:
    any of them
}