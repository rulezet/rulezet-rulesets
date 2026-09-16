rule TTP_XOR_MULT_DOSStub_70de {
  strings:
    $key_70de = { 24 b6 [2] 50 ae [2] 17 ac [2] 50 bd [2] 1e b1 [2] 12 bb [2] 05 b0 [2] 1e fe [2] 23 }

  condition:
    any of them
}