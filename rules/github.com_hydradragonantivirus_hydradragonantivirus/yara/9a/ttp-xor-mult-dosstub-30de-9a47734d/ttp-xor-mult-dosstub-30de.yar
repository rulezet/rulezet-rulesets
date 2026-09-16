rule TTP_XOR_MULT_DOSStub_30de {
  strings:
    $key_30de = { 64 b6 [2] 10 ae [2] 57 ac [2] 10 bd [2] 5e b1 [2] 52 bb [2] 45 b0 [2] 5e fe [2] 63 }

  condition:
    any of them
}