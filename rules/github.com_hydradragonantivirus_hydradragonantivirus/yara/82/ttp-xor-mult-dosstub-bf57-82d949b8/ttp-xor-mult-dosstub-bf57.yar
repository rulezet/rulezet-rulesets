rule TTP_XOR_MULT_DOSStub_bf57 {
  strings:
    $key_bf57 = { eb 3f [2] 9f 27 [2] d8 25 [2] 9f 34 [2] d1 38 [2] dd 32 [2] ca 39 [2] d1 77 [2] ec }

  condition:
    any of them
}