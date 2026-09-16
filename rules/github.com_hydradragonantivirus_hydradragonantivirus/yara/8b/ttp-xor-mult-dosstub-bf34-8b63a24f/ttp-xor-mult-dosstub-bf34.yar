rule TTP_XOR_MULT_DOSStub_bf34 {
  strings:
    $key_bf34 = { eb 5c [2] 9f 44 [2] d8 46 [2] 9f 57 [2] d1 5b [2] dd 51 [2] ca 5a [2] d1 14 [2] ec }

  condition:
    any of them
}