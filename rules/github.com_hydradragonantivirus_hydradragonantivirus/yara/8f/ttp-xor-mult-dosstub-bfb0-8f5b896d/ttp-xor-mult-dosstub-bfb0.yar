rule TTP_XOR_MULT_DOSStub_bfb0 {
  strings:
    $key_bfb0 = { eb d8 [2] 9f c0 [2] d8 c2 [2] 9f d3 [2] d1 df [2] dd d5 [2] ca de [2] d1 90 [2] ec }

  condition:
    any of them
}