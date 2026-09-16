rule TTP_XOR_MULT_DOSStub_bf62 {
  strings:
    $key_bf62 = { eb 0a [2] 9f 12 [2] d8 10 [2] 9f 01 [2] d1 0d [2] dd 07 [2] ca 0c [2] d1 42 [2] ec }

  condition:
    any of them
}