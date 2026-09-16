rule TTP_XOR_MULT_DOSStub_cf9b {
  strings:
    $key_cf9b = { 9b f3 [2] ef eb [2] a8 e9 [2] ef f8 [2] a1 f4 [2] ad fe [2] ba f5 [2] a1 bb [2] 9c }

  condition:
    any of them
}