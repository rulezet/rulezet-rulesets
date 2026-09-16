rule TTP_XOR_MULT_DOSStub_a7de {
  strings:
    $key_a7de = { f3 b6 [2] 87 ae [2] c0 ac [2] 87 bd [2] c9 b1 [2] c5 bb [2] d2 b0 [2] c9 fe [2] f4 }

  condition:
    any of them
}