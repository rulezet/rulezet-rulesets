rule TTP_XOR_MULT_DOSStub_bfbe {
  strings:
    $key_bfbe = { eb d6 [2] 9f ce [2] d8 cc [2] 9f dd [2] d1 d1 [2] dd db [2] ca d0 [2] d1 9e [2] ec }

  condition:
    any of them
}