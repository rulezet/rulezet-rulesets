rule TTP_XOR_MULT_DOSStub_bf5a {
  strings:
    $key_bf5a = { eb 32 [2] 9f 2a [2] d8 28 [2] 9f 39 [2] d1 35 [2] dd 3f [2] ca 34 [2] d1 7a [2] ec }

  condition:
    any of them
}