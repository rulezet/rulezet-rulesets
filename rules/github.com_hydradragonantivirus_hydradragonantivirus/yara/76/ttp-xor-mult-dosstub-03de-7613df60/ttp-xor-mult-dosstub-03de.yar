rule TTP_XOR_MULT_DOSStub_03de {
  strings:
    $key_03de = { 57 b6 [2] 23 ae [2] 64 ac [2] 23 bd [2] 6d b1 [2] 61 bb [2] 76 b0 [2] 6d fe [2] 50 }

  condition:
    any of them
}