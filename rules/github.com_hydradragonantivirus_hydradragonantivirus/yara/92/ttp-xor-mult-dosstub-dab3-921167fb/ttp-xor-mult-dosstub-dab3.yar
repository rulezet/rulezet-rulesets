rule TTP_XOR_MULT_DOSStub_dab3 {
  strings:
    $key_dab3 = { 8e db [2] fa c3 [2] bd c1 [2] fa d0 [2] b4 dc [2] b8 d6 [2] af dd [2] b4 93 [2] 89 }

  condition:
    any of them
}