rule TTP_XOR_MULT_DOSStub_b1de {
  strings:
    $key_b1de = { e5 b6 [2] 91 ae [2] d6 ac [2] 91 bd [2] df b1 [2] d3 bb [2] c4 b0 [2] df fe [2] e2 }

  condition:
    any of them
}