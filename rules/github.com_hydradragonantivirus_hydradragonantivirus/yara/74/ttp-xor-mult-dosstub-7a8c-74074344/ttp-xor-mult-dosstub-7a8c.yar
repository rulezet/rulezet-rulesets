rule TTP_XOR_MULT_DOSStub_7a8c {
  strings:
    $key_7a8c = { 2e e4 [2] 5a fc [2] 1d fe [2] 5a ef [2] 14 e3 [2] 18 e9 [2] 0f e2 [2] 14 ac [2] 29 }

  condition:
    any of them
}