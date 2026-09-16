rule TTP_XOR_MULT_DOSStub_e6de {
  strings:
    $key_e6de = { b2 b6 [2] c6 ae [2] 81 ac [2] c6 bd [2] 88 b1 [2] 84 bb [2] 93 b0 [2] 88 fe [2] b5 }

  condition:
    any of them
}