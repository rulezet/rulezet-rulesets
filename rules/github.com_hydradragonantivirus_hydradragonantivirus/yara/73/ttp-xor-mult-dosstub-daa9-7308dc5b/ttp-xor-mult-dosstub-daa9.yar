rule TTP_XOR_MULT_DOSStub_daa9 {
  strings:
    $key_daa9 = { 8e c1 [2] fa d9 [2] bd db [2] fa ca [2] b4 c6 [2] b8 cc [2] af c7 [2] b4 89 [2] 89 }

  condition:
    any of them
}