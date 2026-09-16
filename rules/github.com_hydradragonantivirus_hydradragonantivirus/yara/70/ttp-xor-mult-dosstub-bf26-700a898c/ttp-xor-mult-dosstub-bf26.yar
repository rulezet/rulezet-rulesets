rule TTP_XOR_MULT_DOSStub_bf26 {
  strings:
    $key_bf26 = { eb 4e [2] 9f 56 [2] d8 54 [2] 9f 45 [2] d1 49 [2] dd 43 [2] ca 48 [2] d1 06 [2] ec }

  condition:
    any of them
}