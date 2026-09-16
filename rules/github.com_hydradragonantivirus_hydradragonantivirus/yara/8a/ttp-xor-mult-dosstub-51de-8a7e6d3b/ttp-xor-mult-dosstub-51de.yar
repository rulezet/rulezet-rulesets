rule TTP_XOR_MULT_DOSStub_51de {
  strings:
    $key_51de = { 05 b6 [2] 71 ae [2] 36 ac [2] 71 bd [2] 3f b1 [2] 33 bb [2] 24 b0 [2] 3f fe [2] 02 }

  condition:
    any of them
}