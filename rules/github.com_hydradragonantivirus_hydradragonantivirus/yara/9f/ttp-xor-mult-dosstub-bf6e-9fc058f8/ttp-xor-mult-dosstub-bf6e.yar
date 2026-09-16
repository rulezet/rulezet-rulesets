rule TTP_XOR_MULT_DOSStub_bf6e {
  strings:
    $key_bf6e = { eb 06 [2] 9f 1e [2] d8 1c [2] 9f 0d [2] d1 01 [2] dd 0b [2] ca 00 [2] d1 4e [2] ec }

  condition:
    any of them
}