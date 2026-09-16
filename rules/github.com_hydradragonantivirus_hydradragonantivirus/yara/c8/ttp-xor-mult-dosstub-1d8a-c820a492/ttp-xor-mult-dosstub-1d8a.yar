rule TTP_XOR_MULT_DOSStub_1d8a {
  strings:
    $key_1d8a = { 49 e2 [2] 3d fa [2] 7a f8 [2] 3d e9 [2] 73 e5 [2] 7f ef [2] 68 e4 [2] 73 aa [2] 4e }

  condition:
    any of them
}