rule TTP_XOR_MULT_DOSStub_528a {
  strings:
    $key_528a = { 06 e2 [2] 72 fa [2] 35 f8 [2] 72 e9 [2] 3c e5 [2] 30 ef [2] 27 e4 [2] 3c aa [2] 01 }

  condition:
    any of them
}