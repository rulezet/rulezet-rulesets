rule TTP_XOR_MULT_DOSStub_628a {
  strings:
    $key_628a = { 36 e2 [2] 42 fa [2] 05 f8 [2] 42 e9 [2] 0c e5 [2] 00 ef [2] 17 e4 [2] 0c aa [2] 31 }

  condition:
    any of them
}