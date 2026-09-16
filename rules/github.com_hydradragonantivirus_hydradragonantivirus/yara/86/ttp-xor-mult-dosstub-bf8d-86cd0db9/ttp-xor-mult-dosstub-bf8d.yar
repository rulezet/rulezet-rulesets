rule TTP_XOR_MULT_DOSStub_bf8d {
  strings:
    $key_bf8d = { eb e5 [2] 9f fd [2] d8 ff [2] 9f ee [2] d1 e2 [2] dd e8 [2] ca e3 [2] d1 ad [2] ec }

  condition:
    any of them
}