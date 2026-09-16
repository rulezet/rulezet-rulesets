rule TTP_XOR_MULT_DOSStub_c1a0 {
  strings:
    $key_c1a0 = { 95 c8 [2] e1 d0 [2] a6 d2 [2] e1 c3 [2] af cf [2] a3 c5 [2] b4 ce [2] af 80 [2] 92 }

  condition:
    any of them
}