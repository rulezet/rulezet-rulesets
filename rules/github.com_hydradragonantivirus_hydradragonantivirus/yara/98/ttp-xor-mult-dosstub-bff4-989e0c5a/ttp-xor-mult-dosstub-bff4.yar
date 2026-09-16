rule TTP_XOR_MULT_DOSStub_bff4 {
  strings:
    $key_bff4 = { eb 9c [2] 9f 84 [2] d8 86 [2] 9f 97 [2] d1 9b [2] dd 91 [2] ca 9a [2] d1 d4 [2] ec }

  condition:
    any of them
}