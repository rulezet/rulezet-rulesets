rule TTP_XOR_MULT_DOSStub_bf5f {
  strings:
    $key_bf5f = { eb 37 [2] 9f 2f [2] d8 2d [2] 9f 3c [2] d1 30 [2] dd 3a [2] ca 31 [2] d1 7f [2] ec }

  condition:
    any of them
}