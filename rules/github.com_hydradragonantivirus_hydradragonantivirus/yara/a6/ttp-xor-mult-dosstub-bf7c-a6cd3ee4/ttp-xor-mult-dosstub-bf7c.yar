rule TTP_XOR_MULT_DOSStub_bf7c {
  strings:
    $key_bf7c = { eb 14 [2] 9f 0c [2] d8 0e [2] 9f 1f [2] d1 13 [2] dd 19 [2] ca 12 [2] d1 5c [2] ec }

  condition:
    any of them
}