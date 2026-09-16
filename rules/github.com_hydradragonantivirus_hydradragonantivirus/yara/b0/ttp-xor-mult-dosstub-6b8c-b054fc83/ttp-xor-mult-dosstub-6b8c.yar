rule TTP_XOR_MULT_DOSStub_6b8c {
  strings:
    $key_6b8c = { 3f e4 [2] 4b fc [2] 0c fe [2] 4b ef [2] 05 e3 [2] 09 e9 [2] 1e e2 [2] 05 ac [2] 38 }

  condition:
    any of them
}