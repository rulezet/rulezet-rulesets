rule TTP_XOR_MULT_DOSStub_bf1a {
  strings:
    $key_bf1a = { eb 72 [2] 9f 6a [2] d8 68 [2] 9f 79 [2] d1 75 [2] dd 7f [2] ca 74 [2] d1 3a [2] ec }

  condition:
    any of them
}