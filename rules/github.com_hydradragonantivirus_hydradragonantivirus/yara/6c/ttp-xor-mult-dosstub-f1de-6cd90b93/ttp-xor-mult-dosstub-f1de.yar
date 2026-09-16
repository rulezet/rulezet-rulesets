rule TTP_XOR_MULT_DOSStub_f1de {
  strings:
    $key_f1de = { a5 b6 [2] d1 ae [2] 96 ac [2] d1 bd [2] 9f b1 [2] 93 bb [2] 84 b0 [2] 9f fe [2] a2 }

  condition:
    any of them
}