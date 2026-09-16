rule TTP_XOR_MULT_DOSStub_728a {
  strings:
    $key_728a = { 26 e2 [2] 52 fa [2] 15 f8 [2] 52 e9 [2] 1c e5 [2] 10 ef [2] 07 e4 [2] 1c aa [2] 21 }

  condition:
    any of them
}