rule TTP_XOR_MULT_DOSStub_62de {
  strings:
    $key_62de = { 36 b6 [2] 42 ae [2] 05 ac [2] 42 bd [2] 0c b1 [2] 00 bb [2] 17 b0 [2] 0c fe [2] 31 }

  condition:
    any of them
}