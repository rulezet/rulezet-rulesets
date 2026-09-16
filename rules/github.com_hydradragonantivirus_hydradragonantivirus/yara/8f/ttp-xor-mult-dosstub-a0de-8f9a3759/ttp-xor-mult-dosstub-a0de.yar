rule TTP_XOR_MULT_DOSStub_a0de {
  strings:
    $key_a0de = { f4 b6 [2] 80 ae [2] c7 ac [2] 80 bd [2] ce b1 [2] c2 bb [2] d5 b0 [2] ce fe [2] f3 }

  condition:
    any of them
}