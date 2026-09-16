rule TTP_XOR_MULT_DOSStub_4d8a {
  strings:
    $key_4d8a = { 19 e2 [2] 6d fa [2] 2a f8 [2] 6d e9 [2] 23 e5 [2] 2f ef [2] 38 e4 [2] 23 aa [2] 1e }

  condition:
    any of them
}