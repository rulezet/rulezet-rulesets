rule TTP_XOR_MULT_DOSStub_bff8 {
  strings:
    $key_bff8 = { eb 90 [2] 9f 88 [2] d8 8a [2] 9f 9b [2] d1 97 [2] dd 9d [2] ca 96 [2] d1 d8 [2] ec }

  condition:
    any of them
}