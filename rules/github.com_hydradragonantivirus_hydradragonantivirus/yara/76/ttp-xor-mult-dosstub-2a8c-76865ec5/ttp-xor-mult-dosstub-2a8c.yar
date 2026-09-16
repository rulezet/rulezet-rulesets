rule TTP_XOR_MULT_DOSStub_2a8c {
  strings:
    $key_2a8c = { 7e e4 [2] 0a fc [2] 4d fe [2] 0a ef [2] 44 e3 [2] 48 e9 [2] 5f e2 [2] 44 ac [2] 79 }

  condition:
    any of them
}