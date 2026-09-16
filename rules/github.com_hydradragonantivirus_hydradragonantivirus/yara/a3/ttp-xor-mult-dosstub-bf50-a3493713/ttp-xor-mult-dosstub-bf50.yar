rule TTP_XOR_MULT_DOSStub_bf50 {
  strings:
    $key_bf50 = { eb 38 [2] 9f 20 [2] d8 22 [2] 9f 33 [2] d1 3f [2] dd 35 [2] ca 3e [2] d1 70 [2] ec }

  condition:
    any of them
}