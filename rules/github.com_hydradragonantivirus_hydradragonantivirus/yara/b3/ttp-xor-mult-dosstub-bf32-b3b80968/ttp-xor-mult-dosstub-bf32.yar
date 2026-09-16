rule TTP_XOR_MULT_DOSStub_bf32 {
  strings:
    $key_bf32 = { eb 5a [2] 9f 42 [2] d8 40 [2] 9f 51 [2] d1 5d [2] dd 57 [2] ca 5c [2] d1 12 [2] ec }

  condition:
    any of them
}