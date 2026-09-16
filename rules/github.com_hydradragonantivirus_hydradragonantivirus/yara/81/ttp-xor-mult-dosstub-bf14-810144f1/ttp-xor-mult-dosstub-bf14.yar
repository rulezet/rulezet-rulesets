rule TTP_XOR_MULT_DOSStub_bf14 {
  strings:
    $key_bf14 = { eb 7c [2] 9f 64 [2] d8 66 [2] 9f 77 [2] d1 7b [2] dd 71 [2] ca 7a [2] d1 34 [2] ec }

  condition:
    any of them
}