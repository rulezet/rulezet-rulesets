rule TTP_XOR_MULT_DOSStub_bf0a {
  strings:
    $key_bf0a = { eb 62 [2] 9f 7a [2] d8 78 [2] 9f 69 [2] d1 65 [2] dd 6f [2] ca 64 [2] d1 2a [2] ec }

  condition:
    any of them
}