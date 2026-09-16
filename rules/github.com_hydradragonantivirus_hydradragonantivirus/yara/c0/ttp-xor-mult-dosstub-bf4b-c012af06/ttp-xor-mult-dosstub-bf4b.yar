rule TTP_XOR_MULT_DOSStub_bf4b {
  strings:
    $key_bf4b = { eb 23 [2] 9f 3b [2] d8 39 [2] 9f 28 [2] d1 24 [2] dd 2e [2] ca 25 [2] d1 6b [2] ec }

  condition:
    any of them
}