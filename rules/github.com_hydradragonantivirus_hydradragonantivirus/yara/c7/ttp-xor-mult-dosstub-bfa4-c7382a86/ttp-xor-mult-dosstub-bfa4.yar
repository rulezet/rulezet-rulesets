rule TTP_XOR_MULT_DOSStub_bfa4 {
  strings:
    $key_bfa4 = { eb cc [2] 9f d4 [2] d8 d6 [2] 9f c7 [2] d1 cb [2] dd c1 [2] ca ca [2] d1 84 [2] ec }

  condition:
    any of them
}