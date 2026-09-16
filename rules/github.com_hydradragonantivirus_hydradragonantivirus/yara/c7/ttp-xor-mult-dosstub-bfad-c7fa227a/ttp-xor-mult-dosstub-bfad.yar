rule TTP_XOR_MULT_DOSStub_bfad {
  strings:
    $key_bfad = { eb c5 [2] 9f dd [2] d8 df [2] 9f ce [2] d1 c2 [2] dd c8 [2] ca c3 [2] d1 8d [2] ec }

  condition:
    any of them
}