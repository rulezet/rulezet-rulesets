rule TTP_XOR_MULT_DOSStub_bf00 {
  strings:
    $key_bf00 = { eb 68 [2] 9f 70 [2] d8 72 [2] 9f 63 [2] d1 6f [2] dd 65 [2] ca 6e [2] d1 20 [2] ec }

  condition:
    any of them
}