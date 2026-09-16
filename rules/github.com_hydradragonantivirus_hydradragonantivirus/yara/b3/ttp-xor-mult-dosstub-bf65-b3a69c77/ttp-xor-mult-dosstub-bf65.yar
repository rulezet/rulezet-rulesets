rule TTP_XOR_MULT_DOSStub_bf65 {
  strings:
    $key_bf65 = { eb 0d [2] 9f 15 [2] d8 17 [2] 9f 06 [2] d1 0a [2] dd 00 [2] ca 0b [2] d1 45 [2] ec }

  condition:
    any of them
}