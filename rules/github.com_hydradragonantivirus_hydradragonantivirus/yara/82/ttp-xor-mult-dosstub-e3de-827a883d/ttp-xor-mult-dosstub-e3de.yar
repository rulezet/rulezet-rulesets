rule TTP_XOR_MULT_DOSStub_e3de {
  strings:
    $key_e3de = { b7 b6 [2] c3 ae [2] 84 ac [2] c3 bd [2] 8d b1 [2] 81 bb [2] 96 b0 [2] 8d fe [2] b0 }

  condition:
    any of them
}