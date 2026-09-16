rule TTP_XOR_MULT_DOSStub_c6ad {
  strings:
    $key_c6ad = { 92 c5 [2] e6 dd [2] a1 df [2] e6 ce [2] a8 c2 [2] a4 c8 [2] b3 c3 [2] a8 8d [2] 95 }

  condition:
    any of them
}