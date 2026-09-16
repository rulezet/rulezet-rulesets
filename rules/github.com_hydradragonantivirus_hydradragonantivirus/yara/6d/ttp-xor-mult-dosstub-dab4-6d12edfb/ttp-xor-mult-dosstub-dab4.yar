rule TTP_XOR_MULT_DOSStub_dab4 {
  strings:
    $key_dab4 = { 8e dc [2] fa c4 [2] bd c6 [2] fa d7 [2] b4 db [2] b8 d1 [2] af da [2] b4 94 [2] 89 }

  condition:
    any of them
}