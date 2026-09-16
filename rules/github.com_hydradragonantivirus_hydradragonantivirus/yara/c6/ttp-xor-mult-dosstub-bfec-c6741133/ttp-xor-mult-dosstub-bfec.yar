rule TTP_XOR_MULT_DOSStub_bfec {
  strings:
    $key_bfec = { eb 84 [2] 9f 9c [2] d8 9e [2] 9f 8f [2] d1 83 [2] dd 89 [2] ca 82 [2] d1 cc [2] ec }

  condition:
    any of them
}