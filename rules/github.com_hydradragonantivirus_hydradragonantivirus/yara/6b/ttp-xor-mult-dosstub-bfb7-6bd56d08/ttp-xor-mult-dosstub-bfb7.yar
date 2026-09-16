rule TTP_XOR_MULT_DOSStub_bfb7 {
  strings:
    $key_bfb7 = { eb df [2] 9f c7 [2] d8 c5 [2] 9f d4 [2] d1 d8 [2] dd d2 [2] ca d9 [2] d1 97 [2] ec }

  condition:
    any of them
}