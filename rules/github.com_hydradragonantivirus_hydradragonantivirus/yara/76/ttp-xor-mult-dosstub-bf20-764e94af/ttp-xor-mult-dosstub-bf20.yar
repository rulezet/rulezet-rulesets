rule TTP_XOR_MULT_DOSStub_bf20 {
  strings:
    $key_bf20 = { eb 48 [2] 9f 50 [2] d8 52 [2] 9f 43 [2] d1 4f [2] dd 45 [2] ca 4e [2] d1 00 [2] ec }

  condition:
    any of them
}