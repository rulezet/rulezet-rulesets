rule TTP_XOR_MULT_DOSStub_048a {
  strings:
    $key_048a = { 50 e2 [2] 24 fa [2] 63 f8 [2] 24 e9 [2] 6a e5 [2] 66 ef [2] 71 e4 [2] 6a aa [2] 57 }

  condition:
    any of them
}