rule TTP_XOR_MULT_DOSStub_bf8f {
  strings:
    $key_bf8f = { eb e7 [2] 9f ff [2] d8 fd [2] 9f ec [2] d1 e0 [2] dd ea [2] ca e1 [2] d1 af [2] ec }

  condition:
    any of them
}