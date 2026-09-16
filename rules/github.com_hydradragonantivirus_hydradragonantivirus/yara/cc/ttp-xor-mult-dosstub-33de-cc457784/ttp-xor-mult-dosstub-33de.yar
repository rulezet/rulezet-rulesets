rule TTP_XOR_MULT_DOSStub_33de {
  strings:
    $key_33de = { 67 b6 [2] 13 ae [2] 54 ac [2] 13 bd [2] 5d b1 [2] 51 bb [2] 46 b0 [2] 5d fe [2] 60 }

  condition:
    any of them
}