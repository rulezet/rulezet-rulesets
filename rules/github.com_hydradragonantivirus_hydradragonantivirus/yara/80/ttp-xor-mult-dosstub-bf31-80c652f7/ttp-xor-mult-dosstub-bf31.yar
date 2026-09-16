rule TTP_XOR_MULT_DOSStub_bf31 {
  strings:
    $key_bf31 = { eb 59 [2] 9f 41 [2] d8 43 [2] 9f 52 [2] d1 5e [2] dd 54 [2] ca 5f [2] d1 11 [2] ec }

  condition:
    any of them
}