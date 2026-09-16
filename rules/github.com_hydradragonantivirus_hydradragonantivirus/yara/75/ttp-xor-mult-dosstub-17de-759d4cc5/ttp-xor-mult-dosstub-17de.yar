rule TTP_XOR_MULT_DOSStub_17de {
  strings:
    $key_17de = { 43 b6 [2] 37 ae [2] 70 ac [2] 37 bd [2] 79 b1 [2] 75 bb [2] 62 b0 [2] 79 fe [2] 44 }

  condition:
    any of them
}