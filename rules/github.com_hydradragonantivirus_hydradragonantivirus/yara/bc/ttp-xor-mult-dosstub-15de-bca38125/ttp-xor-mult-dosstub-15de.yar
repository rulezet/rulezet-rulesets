rule TTP_XOR_MULT_DOSStub_15de {
  strings:
    $key_15de = { 41 b6 [2] 35 ae [2] 72 ac [2] 35 bd [2] 7b b1 [2] 77 bb [2] 60 b0 [2] 7b fe [2] 46 }

  condition:
    any of them
}