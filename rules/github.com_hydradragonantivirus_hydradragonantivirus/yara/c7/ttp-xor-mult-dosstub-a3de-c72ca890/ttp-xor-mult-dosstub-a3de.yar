rule TTP_XOR_MULT_DOSStub_a3de {
  strings:
    $key_a3de = { f7 b6 [2] 83 ae [2] c4 ac [2] 83 bd [2] cd b1 [2] c1 bb [2] d6 b0 [2] cd fe [2] f0 }

  condition:
    any of them
}