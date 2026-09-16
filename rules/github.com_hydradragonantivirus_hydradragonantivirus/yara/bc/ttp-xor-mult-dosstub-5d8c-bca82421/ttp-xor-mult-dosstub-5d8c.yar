rule TTP_XOR_MULT_DOSStub_5d8c {
  strings:
    $key_5d8c = { 09 e4 [2] 7d fc [2] 3a fe [2] 7d ef [2] 33 e3 [2] 3f e9 [2] 28 e2 [2] 33 ac [2] 0e }

  condition:
    any of them
}