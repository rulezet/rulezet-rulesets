rule TTP_XOR_MULT_DOSStub_bf71 {
  strings:
    $key_bf71 = { eb 19 [2] 9f 01 [2] d8 03 [2] 9f 12 [2] d1 1e [2] dd 14 [2] ca 1f [2] d1 51 [2] ec }

  condition:
    any of them
}