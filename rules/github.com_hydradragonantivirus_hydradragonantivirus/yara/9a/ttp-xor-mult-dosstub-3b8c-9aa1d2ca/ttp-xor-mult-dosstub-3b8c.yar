rule TTP_XOR_MULT_DOSStub_3b8c {
  strings:
    $key_3b8c = { 6f e4 [2] 1b fc [2] 5c fe [2] 1b ef [2] 55 e3 [2] 59 e9 [2] 4e e2 [2] 55 ac [2] 68 }

  condition:
    any of them
}