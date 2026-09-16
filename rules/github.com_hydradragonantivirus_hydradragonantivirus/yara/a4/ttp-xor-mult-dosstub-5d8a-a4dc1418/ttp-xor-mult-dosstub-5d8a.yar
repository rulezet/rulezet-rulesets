rule TTP_XOR_MULT_DOSStub_5d8a {
  strings:
    $key_5d8a = { 09 e2 [2] 7d fa [2] 3a f8 [2] 7d e9 [2] 33 e5 [2] 3f ef [2] 28 e4 [2] 33 aa [2] 0e }

  condition:
    any of them
}