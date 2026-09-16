rule TTP_XOR_MULT_DOSStub_a1de {
  strings:
    $key_a1de = { f5 b6 [2] 81 ae [2] c6 ac [2] 81 bd [2] cf b1 [2] c3 bb [2] d4 b0 [2] cf fe [2] f2 }

  condition:
    any of them
}