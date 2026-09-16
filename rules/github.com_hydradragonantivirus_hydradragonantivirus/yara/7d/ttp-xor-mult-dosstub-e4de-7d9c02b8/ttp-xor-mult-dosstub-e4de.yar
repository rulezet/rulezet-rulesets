rule TTP_XOR_MULT_DOSStub_e4de {
  strings:
    $key_e4de = { b0 b6 [2] c4 ae [2] 83 ac [2] c4 bd [2] 8a b1 [2] 86 bb [2] 91 b0 [2] 8a fe [2] b7 }

  condition:
    any of them
}