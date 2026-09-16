rule TTP_XOR_MULT_DOSStub_bfe0 {
  strings:
    $key_bfe0 = { eb 88 [2] 9f 90 [2] d8 92 [2] 9f 83 [2] d1 8f [2] dd 85 [2] ca 8e [2] d1 c0 [2] ec }

  condition:
    any of them
}