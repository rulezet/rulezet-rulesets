rule TTP_XOR_MULT_DOSStub_22de {
  strings:
    $key_22de = { 76 b6 [2] 02 ae [2] 45 ac [2] 02 bd [2] 4c b1 [2] 40 bb [2] 57 b0 [2] 4c fe [2] 71 }

  condition:
    any of them
}