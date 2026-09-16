rule TTP_XOR_MULT_DOSStub_bfee {
  strings:
    $key_bfee = { eb 86 [2] 9f 9e [2] d8 9c [2] 9f 8d [2] d1 81 [2] dd 8b [2] ca 80 [2] d1 ce [2] ec }

  condition:
    any of them
}