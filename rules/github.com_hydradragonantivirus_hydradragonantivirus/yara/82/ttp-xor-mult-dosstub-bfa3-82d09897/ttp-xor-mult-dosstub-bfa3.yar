rule TTP_XOR_MULT_DOSStub_bfa3 {
  strings:
    $key_bfa3 = { eb cb [2] 9f d3 [2] d8 d1 [2] 9f c0 [2] d1 cc [2] dd c6 [2] ca cd [2] d1 83 [2] ec }

  condition:
    any of them
}