rule TTP_XOR_MULT_DOSStub_bf68 {
  strings:
    $key_bf68 = { eb 00 [2] 9f 18 [2] d8 1a [2] 9f 0b [2] d1 07 [2] dd 0d [2] ca 06 [2] d1 48 [2] ec }

  condition:
    any of them
}