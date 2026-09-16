rule TTP_XOR_MULT_DOSStub_e7de {
  strings:
    $key_e7de = { b3 b6 [2] c7 ae [2] 80 ac [2] c7 bd [2] 89 b1 [2] 85 bb [2] 92 b0 [2] 89 fe [2] b4 }

  condition:
    any of them
}