rule TTP_XOR_MULT_DOSStub_bf2a {
  strings:
    $key_bf2a = { eb 42 [2] 9f 5a [2] d8 58 [2] 9f 49 [2] d1 45 [2] dd 4f [2] ca 44 [2] d1 0a [2] ec }

  condition:
    any of them
}