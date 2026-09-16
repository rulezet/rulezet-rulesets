rule TTP_XOR_MULT_DOSStub_0d8a {
  strings:
    $key_0d8a = { 59 e2 [2] 2d fa [2] 6a f8 [2] 2d e9 [2] 63 e5 [2] 6f ef [2] 78 e4 [2] 63 aa [2] 5e }

  condition:
    any of them
}