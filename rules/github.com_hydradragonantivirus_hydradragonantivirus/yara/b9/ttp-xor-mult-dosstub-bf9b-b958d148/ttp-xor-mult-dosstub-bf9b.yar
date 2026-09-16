rule TTP_XOR_MULT_DOSStub_bf9b {
  strings:
    $key_bf9b = { eb f3 [2] 9f eb [2] d8 e9 [2] 9f f8 [2] d1 f4 [2] dd fe [2] ca f5 [2] d1 bb [2] ec }

  condition:
    any of them
}