rule TTP_XOR_MULT_DOSStub_bffe {
  strings:
    $key_bffe = { eb 96 [2] 9f 8e [2] d8 8c [2] 9f 9d [2] d1 91 [2] dd 9b [2] ca 90 [2] d1 de [2] ec }

  condition:
    any of them
}