rule TTP_XOR_MULT_DOSStub_bfb5 {
  strings:
    $key_bfb5 = { eb dd [2] 9f c5 [2] d8 c7 [2] 9f d6 [2] d1 da [2] dd d0 [2] ca db [2] d1 95 [2] ec }

  condition:
    any of them
}