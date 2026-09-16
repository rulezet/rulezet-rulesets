rule TTP_XOR_MULT_DOSStub_86de {
  strings:
    $key_86de = { d2 b6 [2] a6 ae [2] e1 ac [2] a6 bd [2] e8 b1 [2] e4 bb [2] f3 b0 [2] e8 fe [2] d5 }

  condition:
    any of them
}