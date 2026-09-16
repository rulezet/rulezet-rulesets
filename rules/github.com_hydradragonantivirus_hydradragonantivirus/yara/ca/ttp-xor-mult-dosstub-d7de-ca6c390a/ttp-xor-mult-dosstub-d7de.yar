rule TTP_XOR_MULT_DOSStub_d7de {
  strings:
    $key_d7de = { 83 b6 [2] f7 ae [2] b0 ac [2] f7 bd [2] b9 b1 [2] b5 bb [2] a2 b0 [2] b9 fe [2] 84 }

  condition:
    any of them
}