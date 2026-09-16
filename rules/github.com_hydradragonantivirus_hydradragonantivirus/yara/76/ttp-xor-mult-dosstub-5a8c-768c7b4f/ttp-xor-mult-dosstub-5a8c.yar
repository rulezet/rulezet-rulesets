rule TTP_XOR_MULT_DOSStub_5a8c {
  strings:
    $key_5a8c = { 0e e4 [2] 7a fc [2] 3d fe [2] 7a ef [2] 34 e3 [2] 38 e9 [2] 2f e2 [2] 34 ac [2] 09 }

  condition:
    any of them
}