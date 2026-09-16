rule TTP_XOR_MULT_DOSStub_1b8a {
  strings:
    $key_1b8a = { 4f e2 [2] 3b fa [2] 7c f8 [2] 3b e9 [2] 75 e5 [2] 79 ef [2] 6e e4 [2] 75 aa [2] 48 }

  condition:
    any of them
}