rule TTP_XOR_MULT_DOSStub_41de {
  strings:
    $key_41de = { 15 b6 [2] 61 ae [2] 26 ac [2] 61 bd [2] 2f b1 [2] 23 bb [2] 34 b0 [2] 2f fe [2] 12 }

  condition:
    any of them
}