rule TTP_XOR_MULT_DOSStub_12de {
  strings:
    $key_12de = { 46 b6 [2] 32 ae [2] 75 ac [2] 32 bd [2] 7c b1 [2] 70 bb [2] 67 b0 [2] 7c fe [2] 41 }

  condition:
    any of them
}