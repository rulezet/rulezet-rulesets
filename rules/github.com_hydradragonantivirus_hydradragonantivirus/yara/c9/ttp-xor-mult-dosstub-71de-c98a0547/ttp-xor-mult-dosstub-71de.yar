rule TTP_XOR_MULT_DOSStub_71de {
  strings:
    $key_71de = { 25 b6 [2] 51 ae [2] 16 ac [2] 51 bd [2] 1f b1 [2] 13 bb [2] 04 b0 [2] 1f fe [2] 22 }

  condition:
    any of them
}