rule TTP_XOR_MULT_DOSStub_bfa2 {
  strings:
    $key_bfa2 = { eb ca [2] 9f d2 [2] d8 d0 [2] 9f c1 [2] d1 cd [2] dd c7 [2] ca cc [2] d1 82 [2] ec }

  condition:
    any of them
}