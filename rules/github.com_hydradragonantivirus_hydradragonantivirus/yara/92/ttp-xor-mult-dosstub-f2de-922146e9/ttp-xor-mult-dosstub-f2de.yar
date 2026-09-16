rule TTP_XOR_MULT_DOSStub_f2de {
  strings:
    $key_f2de = { a6 b6 [2] d2 ae [2] 95 ac [2] d2 bd [2] 9c b1 [2] 90 bb [2] 87 b0 [2] 9c fe [2] a1 }

  condition:
    any of them
}