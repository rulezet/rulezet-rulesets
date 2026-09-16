rule TTP_XOR_MULT_DOSStub_14de {
  strings:
    $key_14de = { 40 b6 [2] 34 ae [2] 73 ac [2] 34 bd [2] 7a b1 [2] 76 bb [2] 61 b0 [2] 7a fe [2] 47 }

  condition:
    any of them
}