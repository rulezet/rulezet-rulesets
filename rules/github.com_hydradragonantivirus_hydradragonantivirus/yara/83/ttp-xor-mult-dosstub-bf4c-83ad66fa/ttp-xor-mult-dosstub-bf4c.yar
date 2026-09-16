rule TTP_XOR_MULT_DOSStub_bf4c {
  strings:
    $key_bf4c = { eb 24 [2] 9f 3c [2] d8 3e [2] 9f 2f [2] d1 23 [2] dd 29 [2] ca 22 [2] d1 6c [2] ec }

  condition:
    any of them
}