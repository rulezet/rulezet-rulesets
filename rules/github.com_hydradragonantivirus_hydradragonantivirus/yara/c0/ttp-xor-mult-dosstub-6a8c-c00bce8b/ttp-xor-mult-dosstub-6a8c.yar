rule TTP_XOR_MULT_DOSStub_6a8c {
  strings:
    $key_6a8c = { 3e e4 [2] 4a fc [2] 0d fe [2] 4a ef [2] 04 e3 [2] 08 e9 [2] 1f e2 [2] 04 ac [2] 39 }

  condition:
    any of them
}