rule TTP_XOR_MULT_DOSStub_c6be {
  strings:
    $key_c6be = { 92 d6 [2] e6 ce [2] a1 cc [2] e6 dd [2] a8 d1 [2] a4 db [2] b3 d0 [2] a8 9e [2] 95 }

  condition:
    any of them
}