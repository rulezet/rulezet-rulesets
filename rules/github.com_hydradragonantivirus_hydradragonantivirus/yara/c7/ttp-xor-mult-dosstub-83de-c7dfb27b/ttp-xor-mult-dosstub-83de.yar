rule TTP_XOR_MULT_DOSStub_83de {
  strings:
    $key_83de = { d7 b6 [2] a3 ae [2] e4 ac [2] a3 bd [2] ed b1 [2] e1 bb [2] f6 b0 [2] ed fe [2] d0 }

  condition:
    any of them
}