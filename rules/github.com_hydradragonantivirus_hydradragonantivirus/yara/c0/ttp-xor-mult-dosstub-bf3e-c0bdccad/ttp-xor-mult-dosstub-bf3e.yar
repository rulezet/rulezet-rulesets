rule TTP_XOR_MULT_DOSStub_bf3e {
  strings:
    $key_bf3e = { eb 56 [2] 9f 4e [2] d8 4c [2] 9f 5d [2] d1 51 [2] dd 5b [2] ca 50 [2] d1 1e [2] ec }

  condition:
    any of them
}