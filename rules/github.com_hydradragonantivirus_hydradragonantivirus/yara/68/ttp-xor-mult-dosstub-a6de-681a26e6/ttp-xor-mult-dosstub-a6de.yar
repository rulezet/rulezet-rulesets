rule TTP_XOR_MULT_DOSStub_a6de {
  strings:
    $key_a6de = { f2 b6 [2] 86 ae [2] c1 ac [2] 86 bd [2] c8 b1 [2] c4 bb [2] d3 b0 [2] c8 fe [2] f5 }

  condition:
    any of them
}