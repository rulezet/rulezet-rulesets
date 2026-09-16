rule TTP_XOR_MULT_DOSStub_c3de {
  strings:
    $key_c3de = { 97 b6 [2] e3 ae [2] a4 ac [2] e3 bd [2] ad b1 [2] a1 bb [2] b6 b0 [2] ad fe [2] 90 }

  condition:
    any of them
}