rule TTP_XOR_MULT_DOSStub_dab2 {
  strings:
    $key_dab2 = { 8e da [2] fa c2 [2] bd c0 [2] fa d1 [2] b4 dd [2] b8 d7 [2] af dc [2] b4 92 [2] 89 }

  condition:
    any of them
}