rule TTP_XOR_MULT_DOSStub_c6ab {
  strings:
    $key_c6ab = { 92 c3 [2] e6 db [2] a1 d9 [2] e6 c8 [2] a8 c4 [2] a4 ce [2] b3 c5 [2] a8 8b [2] 95 }

  condition:
    any of them
}