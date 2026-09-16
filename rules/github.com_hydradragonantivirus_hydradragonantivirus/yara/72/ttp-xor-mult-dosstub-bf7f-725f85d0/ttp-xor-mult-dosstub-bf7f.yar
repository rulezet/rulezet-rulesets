rule TTP_XOR_MULT_DOSStub_bf7f {
  strings:
    $key_bf7f = { eb 17 [2] 9f 0f [2] d8 0d [2] 9f 1c [2] d1 10 [2] dd 1a [2] ca 11 [2] d1 5f [2] ec }

  condition:
    any of them
}