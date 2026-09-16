rule TTP_XOR_MULT_DOSStub_3d8a {
  strings:
    $key_3d8a = { 69 e2 [2] 1d fa [2] 5a f8 [2] 1d e9 [2] 53 e5 [2] 5f ef [2] 48 e4 [2] 53 aa [2] 6e }

  condition:
    any of them
}