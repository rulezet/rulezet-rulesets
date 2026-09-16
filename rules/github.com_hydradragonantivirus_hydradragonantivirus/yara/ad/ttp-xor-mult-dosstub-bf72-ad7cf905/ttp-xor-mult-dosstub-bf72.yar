rule TTP_XOR_MULT_DOSStub_bf72 {
  strings:
    $key_bf72 = { eb 1a [2] 9f 02 [2] d8 00 [2] 9f 11 [2] d1 1d [2] dd 17 [2] ca 1c [2] d1 52 [2] ec }

  condition:
    any of them
}