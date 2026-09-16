rule TTP_XOR_MULT_DOSStub_bf4a {
  strings:
    $key_bf4a = { eb 22 [2] 9f 3a [2] d8 38 [2] 9f 29 [2] d1 25 [2] dd 2f [2] ca 24 [2] d1 6a [2] ec }

  condition:
    any of them
}