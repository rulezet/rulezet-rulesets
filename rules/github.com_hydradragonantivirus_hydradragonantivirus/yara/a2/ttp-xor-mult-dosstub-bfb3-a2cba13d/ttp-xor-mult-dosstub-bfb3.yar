rule TTP_XOR_MULT_DOSStub_bfb3 {
  strings:
    $key_bfb3 = { eb db [2] 9f c3 [2] d8 c1 [2] 9f d0 [2] d1 dc [2] dd d6 [2] ca dd [2] d1 93 [2] ec }

  condition:
    any of them
}