rule TTP_XOR_MULT_DOSStub_bc8c {
  strings:
    $key_bc8c = { e8 e4 [2] 9c fc [2] db fe [2] 9c ef [2] d2 e3 [2] de e9 [2] c9 e2 [2] d2 ac [2] ef }

  condition:
    any of them
}