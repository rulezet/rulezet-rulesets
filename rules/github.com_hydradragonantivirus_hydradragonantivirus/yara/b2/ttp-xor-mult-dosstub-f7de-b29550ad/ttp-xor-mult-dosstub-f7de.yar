rule TTP_XOR_MULT_DOSStub_f7de {
  strings:
    $key_f7de = { a3 b6 [2] d7 ae [2] 90 ac [2] d7 bd [2] 99 b1 [2] 95 bb [2] 82 b0 [2] 99 fe [2] a4 }

  condition:
    any of them
}