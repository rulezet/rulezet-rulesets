rule TTP_XOR_MULT_DOSStub_2d8a {
  strings:
    $key_2d8a = { 79 e2 [2] 0d fa [2] 4a f8 [2] 0d e9 [2] 43 e5 [2] 4f ef [2] 58 e4 [2] 43 aa [2] 7e }

  condition:
    any of them
}