rule TTP_XOR_MULT_DOSStub_bf0d {
  strings:
    $key_bf0d = { eb 65 [2] 9f 7d [2] d8 7f [2] 9f 6e [2] d1 62 [2] dd 68 [2] ca 63 [2] d1 2d [2] ec }

  condition:
    any of them
}