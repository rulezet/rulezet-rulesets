rule TTP_XOR_MULT_DOSStub_57de {
  strings:
    $key_57de = { 03 b6 [2] 77 ae [2] 30 ac [2] 77 bd [2] 39 b1 [2] 35 bb [2] 22 b0 [2] 39 fe [2] 04 }

  condition:
    any of them
}