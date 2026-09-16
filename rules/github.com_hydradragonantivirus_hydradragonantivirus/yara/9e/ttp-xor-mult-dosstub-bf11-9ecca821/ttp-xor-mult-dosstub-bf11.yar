rule TTP_XOR_MULT_DOSStub_bf11 {
  strings:
    $key_bf11 = { eb 79 [2] 9f 61 [2] d8 63 [2] 9f 72 [2] d1 7e [2] dd 74 [2] ca 7f [2] d1 31 [2] ec }

  condition:
    any of them
}