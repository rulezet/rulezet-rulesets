rule TTP_XOR_MULT_DOSStub_bfa9 {
  strings:
    $key_bfa9 = { eb c1 [2] 9f d9 [2] d8 db [2] 9f ca [2] d1 c6 [2] dd cc [2] ca c7 [2] d1 89 [2] ec }

  condition:
    any of them
}