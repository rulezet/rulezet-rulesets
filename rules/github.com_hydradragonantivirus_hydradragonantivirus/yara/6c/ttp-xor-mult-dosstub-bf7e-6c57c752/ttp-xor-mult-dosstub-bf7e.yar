rule TTP_XOR_MULT_DOSStub_bf7e {
  strings:
    $key_bf7e = { eb 16 [2] 9f 0e [2] d8 0c [2] 9f 1d [2] d1 11 [2] dd 1b [2] ca 10 [2] d1 5e [2] ec }

  condition:
    any of them
}