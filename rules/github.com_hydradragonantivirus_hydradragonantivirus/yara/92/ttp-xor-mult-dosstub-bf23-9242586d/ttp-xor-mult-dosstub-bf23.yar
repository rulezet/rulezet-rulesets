rule TTP_XOR_MULT_DOSStub_bf23 {
  strings:
    $key_bf23 = { eb 4b [2] 9f 53 [2] d8 51 [2] 9f 40 [2] d1 4c [2] dd 46 [2] ca 4d [2] d1 03 [2] ec }

  condition:
    any of them
}