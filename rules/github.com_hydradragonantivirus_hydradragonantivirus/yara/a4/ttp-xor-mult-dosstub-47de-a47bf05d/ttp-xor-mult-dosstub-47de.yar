rule TTP_XOR_MULT_DOSStub_47de {
  strings:
    $key_47de = { 13 b6 [2] 67 ae [2] 20 ac [2] 67 bd [2] 29 b1 [2] 25 bb [2] 32 b0 [2] 29 fe [2] 14 }

  condition:
    any of them
}