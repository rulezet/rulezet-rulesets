rule TTP_XOR_MULT_DOSStub_4a8a {
  strings:
    $key_4a8a = { 1e e2 [2] 6a fa [2] 2d f8 [2] 6a e9 [2] 24 e5 [2] 28 ef [2] 3f e4 [2] 24 aa [2] 19 }

  condition:
    any of them
}