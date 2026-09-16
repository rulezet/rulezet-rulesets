rule TTP_XOR_MULT_DOSStub_4a8c {
  strings:
    $key_4a8c = { 1e e4 [2] 6a fc [2] 2d fe [2] 6a ef [2] 24 e3 [2] 28 e9 [2] 3f e2 [2] 24 ac [2] 19 }

  condition:
    any of them
}