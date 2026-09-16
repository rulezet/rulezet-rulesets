rule TTP_XOR_MULT_DOSStub_bf6d {
  strings:
    $key_bf6d = { eb 05 [2] 9f 1d [2] d8 1f [2] 9f 0e [2] d1 02 [2] dd 08 [2] ca 03 [2] d1 4d [2] ec }

  condition:
    any of them
}