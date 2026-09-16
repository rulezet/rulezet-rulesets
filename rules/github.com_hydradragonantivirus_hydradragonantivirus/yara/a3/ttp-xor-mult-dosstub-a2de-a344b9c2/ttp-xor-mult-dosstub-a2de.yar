rule TTP_XOR_MULT_DOSStub_a2de {
  strings:
    $key_a2de = { f6 b6 [2] 82 ae [2] c5 ac [2] 82 bd [2] cc b1 [2] c0 bb [2] d7 b0 [2] cc fe [2] f1 }

  condition:
    any of them
}