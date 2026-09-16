rule TTP_XOR_MULT_DOSStub_d5de {
  strings:
    $key_d5de = { 81 b6 [2] f5 ae [2] b2 ac [2] f5 bd [2] bb b1 [2] b7 bb [2] a0 b0 [2] bb fe [2] 86 }

  condition:
    any of them
}