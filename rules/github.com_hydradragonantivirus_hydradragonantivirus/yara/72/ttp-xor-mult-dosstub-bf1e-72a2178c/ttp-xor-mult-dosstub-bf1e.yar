rule TTP_XOR_MULT_DOSStub_bf1e {
  strings:
    $key_bf1e = { eb 76 [2] 9f 6e [2] d8 6c [2] 9f 7d [2] d1 71 [2] dd 7b [2] ca 70 [2] d1 3e [2] ec }

  condition:
    any of them
}