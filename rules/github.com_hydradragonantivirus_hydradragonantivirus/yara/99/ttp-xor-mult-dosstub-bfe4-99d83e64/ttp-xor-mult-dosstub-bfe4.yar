rule TTP_XOR_MULT_DOSStub_bfe4 {
  strings:
    $key_bfe4 = { eb 8c [2] 9f 94 [2] d8 96 [2] 9f 87 [2] d1 8b [2] dd 81 [2] ca 8a [2] d1 c4 [2] ec }

  condition:
    any of them
}