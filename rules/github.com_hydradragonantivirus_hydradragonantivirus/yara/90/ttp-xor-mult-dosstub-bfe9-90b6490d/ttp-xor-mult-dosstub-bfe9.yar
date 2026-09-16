rule TTP_XOR_MULT_DOSStub_bfe9 {
  strings:
    $key_bfe9 = { eb 81 [2] 9f 99 [2] d8 9b [2] 9f 8a [2] d1 86 [2] dd 8c [2] ca 87 [2] d1 c9 [2] ec }

  condition:
    any of them
}