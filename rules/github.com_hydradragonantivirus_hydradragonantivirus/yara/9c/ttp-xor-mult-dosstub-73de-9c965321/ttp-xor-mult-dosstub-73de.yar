rule TTP_XOR_MULT_DOSStub_73de {
  strings:
    $key_73de = { 27 b6 [2] 53 ae [2] 14 ac [2] 53 bd [2] 1d b1 [2] 11 bb [2] 06 b0 [2] 1d fe [2] 20 }

  condition:
    any of them
}