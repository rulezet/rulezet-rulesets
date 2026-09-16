rule TTP_XOR_MULT_DOSStub_bf7a {
  strings:
    $key_bf7a = { eb 12 [2] 9f 0a [2] d8 08 [2] 9f 19 [2] d1 15 [2] dd 1f [2] ca 14 [2] d1 5a [2] ec }

  condition:
    any of them
}