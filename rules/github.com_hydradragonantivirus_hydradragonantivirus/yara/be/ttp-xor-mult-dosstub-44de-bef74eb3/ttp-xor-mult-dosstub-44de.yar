rule TTP_XOR_MULT_DOSStub_44de {
  strings:
    $key_44de = { 10 b6 [2] 64 ae [2] 23 ac [2] 64 bd [2] 2a b1 [2] 26 bb [2] 31 b0 [2] 2a fe [2] 17 }

  condition:
    any of them
}