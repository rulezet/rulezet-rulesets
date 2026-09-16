rule TTP_XOR_MULT_DOSStub_bfba {
  strings:
    $key_bfba = { eb d2 [2] 9f ca [2] d8 c8 [2] 9f d9 [2] d1 d5 [2] dd df [2] ca d4 [2] d1 9a [2] ec }

  condition:
    any of them
}