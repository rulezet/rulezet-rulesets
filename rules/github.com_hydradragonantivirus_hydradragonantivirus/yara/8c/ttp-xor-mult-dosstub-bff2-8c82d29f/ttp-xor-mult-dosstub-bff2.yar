rule TTP_XOR_MULT_DOSStub_bff2 {
  strings:
    $key_bff2 = { eb 9a [2] 9f 82 [2] d8 80 [2] 9f 91 [2] d1 9d [2] dd 97 [2] ca 9c [2] d1 d2 [2] ec }

  condition:
    any of them
}