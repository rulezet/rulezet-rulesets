rule TTP_XOR_MULT_DOSStub_bf46 {
  strings:
    $key_bf46 = { eb 2e [2] 9f 36 [2] d8 34 [2] 9f 25 [2] d1 29 [2] dd 23 [2] ca 28 [2] d1 66 [2] ec }

  condition:
    any of them
}