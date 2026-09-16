rule TTP_XOR_MULT_DOSStub_55de {
  strings:
    $key_55de = { 01 b6 [2] 75 ae [2] 32 ac [2] 75 bd [2] 3b b1 [2] 37 bb [2] 20 b0 [2] 3b fe [2] 06 }

  condition:
    any of them
}