rule TTP_XOR_MULT_DOSStub_05de {
  strings:
    $key_05de = { 51 b6 [2] 25 ae [2] 62 ac [2] 25 bd [2] 6b b1 [2] 67 bb [2] 70 b0 [2] 6b fe [2] 56 }

  condition:
    any of them
}