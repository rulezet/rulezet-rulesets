rule TTP_XOR_MULT_DOSStub_bf49 {
  strings:
    $key_bf49 = { eb 21 [2] 9f 39 [2] d8 3b [2] 9f 2a [2] d1 26 [2] dd 2c [2] ca 27 [2] d1 69 [2] ec }

  condition:
    any of them
}