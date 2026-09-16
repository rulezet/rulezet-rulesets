rule TTP_XOR_MULT_DOSStub_808c {
  strings:
    $key_808c = { d4 e4 [2] a0 fc [2] e7 fe [2] a0 ef [2] ee e3 [2] e2 e9 [2] f5 e2 [2] ee ac [2] d3 }

  condition:
    any of them
}