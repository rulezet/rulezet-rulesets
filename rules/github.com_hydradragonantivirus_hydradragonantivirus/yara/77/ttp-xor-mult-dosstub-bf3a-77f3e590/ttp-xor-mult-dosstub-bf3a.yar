rule TTP_XOR_MULT_DOSStub_bf3a {
  strings:
    $key_bf3a = { eb 52 [2] 9f 4a [2] d8 48 [2] 9f 59 [2] d1 55 [2] dd 5f [2] ca 54 [2] d1 1a [2] ec }

  condition:
    any of them
}