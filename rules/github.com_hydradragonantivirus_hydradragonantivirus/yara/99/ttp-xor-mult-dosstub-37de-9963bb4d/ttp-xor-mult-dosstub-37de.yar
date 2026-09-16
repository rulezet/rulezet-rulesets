rule TTP_XOR_MULT_DOSStub_37de {
  strings:
    $key_37de = { 63 b6 [2] 17 ae [2] 50 ac [2] 17 bd [2] 59 b1 [2] 55 bb [2] 42 b0 [2] 59 fe [2] 64 }

  condition:
    any of them
}