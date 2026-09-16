rule TTP_XOR_MULT_DOSStub_bf25 {
  strings:
    $key_bf25 = { eb 4d [2] 9f 55 [2] d8 57 [2] 9f 46 [2] d1 4a [2] dd 40 [2] ca 4b [2] d1 05 [2] ec }

  condition:
    any of them
}