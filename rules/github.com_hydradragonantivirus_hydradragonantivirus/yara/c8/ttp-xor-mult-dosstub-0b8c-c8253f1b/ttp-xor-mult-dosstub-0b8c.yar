rule TTP_XOR_MULT_DOSStub_0b8c {
  strings:
    $key_0b8c = { 5f e4 [2] 2b fc [2] 6c fe [2] 2b ef [2] 65 e3 [2] 69 e9 [2] 7e e2 [2] 65 ac [2] 58 }

  condition:
    any of them
}