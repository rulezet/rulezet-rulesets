rule TTP_XOR_MULT_DOSStub_448a {
  strings:
    $key_448a = { 10 e2 [2] 64 fa [2] 23 f8 [2] 64 e9 [2] 2a e5 [2] 26 ef [2] 31 e4 [2] 2a aa [2] 17 }

  condition:
    any of them
}