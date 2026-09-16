rule TTP_XOR_MULT_DOSStub_bf1d {
  strings:
    $key_bf1d = { eb 75 [2] 9f 6d [2] d8 6f [2] 9f 7e [2] d1 72 [2] dd 78 [2] ca 73 [2] d1 3d [2] ec }

  condition:
    any of them
}