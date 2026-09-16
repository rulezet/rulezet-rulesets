rule TTP_XOR_MULT_DOSStub_bf02 {
  strings:
    $key_bf02 = { eb 6a [2] 9f 72 [2] d8 70 [2] 9f 61 [2] d1 6d [2] dd 67 [2] ca 6c [2] d1 22 [2] ec }

  condition:
    any of them
}