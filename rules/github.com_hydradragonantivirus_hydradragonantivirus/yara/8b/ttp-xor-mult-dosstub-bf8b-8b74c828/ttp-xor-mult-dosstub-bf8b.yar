rule TTP_XOR_MULT_DOSStub_bf8b {
  strings:
    $key_bf8b = { eb e3 [2] 9f fb [2] d8 f9 [2] 9f e8 [2] d1 e4 [2] dd ee [2] ca e5 [2] d1 ab [2] ec }

  condition:
    any of them
}