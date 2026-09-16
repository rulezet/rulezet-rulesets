rule TTP_XOR_MULT_DOSStub_bf09 {
  strings:
    $key_bf09 = { eb 61 [2] 9f 79 [2] d8 7b [2] 9f 6a [2] d1 66 [2] dd 6c [2] ca 67 [2] d1 29 [2] ec }

  condition:
    any of them
}