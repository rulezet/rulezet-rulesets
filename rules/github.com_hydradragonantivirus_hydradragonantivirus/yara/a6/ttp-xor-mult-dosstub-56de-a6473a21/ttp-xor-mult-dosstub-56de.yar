rule TTP_XOR_MULT_DOSStub_56de {
  strings:
    $key_56de = { 02 b6 [2] 76 ae [2] 31 ac [2] 76 bd [2] 38 b1 [2] 34 bb [2] 23 b0 [2] 38 fe [2] 05 }

  condition:
    any of them
}