rule TTP_XOR_MULT_DOSStub_bf4e {
  strings:
    $key_bf4e = { eb 26 [2] 9f 3e [2] d8 3c [2] 9f 2d [2] d1 21 [2] dd 2b [2] ca 20 [2] d1 6e [2] ec }

  condition:
    any of them
}