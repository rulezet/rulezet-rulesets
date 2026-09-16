rule TTP_XOR_MULT_DOSStub_bf33 {
  strings:
    $key_bf33 = { eb 5b [2] 9f 43 [2] d8 41 [2] 9f 50 [2] d1 5c [2] dd 56 [2] ca 5d [2] d1 13 [2] ec }

  condition:
    any of them
}