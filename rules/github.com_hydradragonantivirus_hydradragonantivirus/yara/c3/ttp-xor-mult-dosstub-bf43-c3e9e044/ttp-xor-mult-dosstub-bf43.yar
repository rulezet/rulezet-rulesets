rule TTP_XOR_MULT_DOSStub_bf43 {
  strings:
    $key_bf43 = { eb 2b [2] 9f 33 [2] d8 31 [2] 9f 20 [2] d1 2c [2] dd 26 [2] ca 2d [2] d1 63 [2] ec }

  condition:
    any of them
}