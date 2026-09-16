rule TTP_XOR_MULT_DOSStub_13de {
  strings:
    $key_13de = { 47 b6 [2] 33 ae [2] 74 ac [2] 33 bd [2] 7d b1 [2] 71 bb [2] 66 b0 [2] 7d fe [2] 40 }

  condition:
    any of them
}