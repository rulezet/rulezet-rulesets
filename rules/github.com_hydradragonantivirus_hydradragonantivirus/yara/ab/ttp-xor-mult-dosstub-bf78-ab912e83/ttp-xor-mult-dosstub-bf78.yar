rule TTP_XOR_MULT_DOSStub_bf78 {
  strings:
    $key_bf78 = { eb 10 [2] 9f 08 [2] d8 0a [2] 9f 1b [2] d1 17 [2] dd 1d [2] ca 16 [2] d1 58 [2] ec }

  condition:
    any of them
}