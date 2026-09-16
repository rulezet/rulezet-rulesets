rule TTP_XOR_MULT_DOSStub_bf76 {
  strings:
    $key_bf76 = { eb 1e [2] 9f 06 [2] d8 04 [2] 9f 15 [2] d1 19 [2] dd 13 [2] ca 18 [2] d1 56 [2] ec }

  condition:
    any of them
}