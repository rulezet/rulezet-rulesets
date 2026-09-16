rule TTP_XOR_MULT_DOSStub_bf03 {
  strings:
    $key_bf03 = { eb 6b [2] 9f 73 [2] d8 71 [2] 9f 60 [2] d1 6c [2] dd 66 [2] ca 6d [2] d1 23 [2] ec }

  condition:
    any of them
}