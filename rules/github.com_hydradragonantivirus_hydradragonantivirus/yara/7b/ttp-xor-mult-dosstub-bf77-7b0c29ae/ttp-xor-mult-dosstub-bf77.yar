rule TTP_XOR_MULT_DOSStub_bf77 {
  strings:
    $key_bf77 = { eb 1f [2] 9f 07 [2] d8 05 [2] 9f 14 [2] d1 18 [2] dd 12 [2] ca 19 [2] d1 57 [2] ec }

  condition:
    any of them
}