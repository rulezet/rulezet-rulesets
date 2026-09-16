rule TTP_XOR_MULT_DOSStub_bfab {
  strings:
    $key_bfab = { eb c3 [2] 9f db [2] d8 d9 [2] 9f c8 [2] d1 c4 [2] dd ce [2] ca c5 [2] d1 8b [2] ec }

  condition:
    any of them
}