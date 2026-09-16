rule TTP_XOR_MULT_DOSStub_bf06 {
  strings:
    $key_bf06 = { eb 6e [2] 9f 76 [2] d8 74 [2] 9f 65 [2] d1 69 [2] dd 63 [2] ca 68 [2] d1 26 [2] ec }

  condition:
    any of them
}