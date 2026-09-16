rule TTP_XOR_MULT_DOSStub_bf75 {
  strings:
    $key_bf75 = { eb 1d [2] 9f 05 [2] d8 07 [2] 9f 16 [2] d1 1a [2] dd 10 [2] ca 1b [2] d1 55 [2] ec }

  condition:
    any of them
}