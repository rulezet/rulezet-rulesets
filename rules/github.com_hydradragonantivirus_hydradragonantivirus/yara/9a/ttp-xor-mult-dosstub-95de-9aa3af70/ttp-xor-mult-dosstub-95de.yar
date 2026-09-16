rule TTP_XOR_MULT_DOSStub_95de {
  strings:
    $key_95de = { c1 b6 [2] b5 ae [2] f2 ac [2] b5 bd [2] fb b1 [2] f7 bb [2] e0 b0 [2] fb fe [2] c6 }

  condition:
    any of them
}