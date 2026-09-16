rule TTP_XOR_MULT_DOSStub_228a {
  strings:
    $key_228a = { 76 e2 [2] 02 fa [2] 45 f8 [2] 02 e9 [2] 4c e5 [2] 40 ef [2] 57 e4 [2] 4c aa [2] 71 }

  condition:
    any of them
}