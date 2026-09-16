rule TTP_XOR_MULT_DOSStub_c6b8 {
  strings:
    $key_c6b8 = { 92 d0 [2] e6 c8 [2] a1 ca [2] e6 db [2] a8 d7 [2] a4 dd [2] b3 d6 [2] a8 98 [2] 95 }

  condition:
    any of them
}