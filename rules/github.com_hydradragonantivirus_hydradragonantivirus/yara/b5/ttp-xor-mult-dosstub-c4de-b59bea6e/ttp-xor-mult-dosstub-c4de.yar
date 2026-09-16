rule TTP_XOR_MULT_DOSStub_c4de {
  strings:
    $key_c4de = { 90 b6 [2] e4 ae [2] a3 ac [2] e4 bd [2] aa b1 [2] a6 bb [2] b1 b0 [2] aa fe [2] 97 }

  condition:
    any of them
}