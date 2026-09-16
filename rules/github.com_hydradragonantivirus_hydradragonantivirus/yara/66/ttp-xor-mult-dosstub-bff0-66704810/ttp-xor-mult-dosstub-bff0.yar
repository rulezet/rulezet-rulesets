rule TTP_XOR_MULT_DOSStub_bff0 {
  strings:
    $key_bff0 = { eb 98 [2] 9f 80 [2] d8 82 [2] 9f 93 [2] d1 9f [2] dd 95 [2] ca 9e [2] d1 d0 [2] ec }

  condition:
    any of them
}