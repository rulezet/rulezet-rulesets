rule TTP_XOR_MULT_DOSStub_e0de {
  strings:
    $key_e0de = { b4 b6 [2] c0 ae [2] 87 ac [2] c0 bd [2] 8e b1 [2] 82 bb [2] 95 b0 [2] 8e fe [2] b3 }

  condition:
    any of them
}