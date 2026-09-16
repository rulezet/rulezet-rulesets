rule TTP_XOR_MULT_DOSStub_e1de {
  strings:
    $key_e1de = { b5 b6 [2] c1 ae [2] 86 ac [2] c1 bd [2] 8f b1 [2] 83 bb [2] 94 b0 [2] 8f fe [2] b2 }

  condition:
    any of them
}