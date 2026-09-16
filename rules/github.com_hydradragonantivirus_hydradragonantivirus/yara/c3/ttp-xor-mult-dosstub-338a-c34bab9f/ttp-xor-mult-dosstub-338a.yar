rule TTP_XOR_MULT_DOSStub_338a {
  strings:
    $key_338a = { 67 e2 [2] 13 fa [2] 54 f8 [2] 13 e9 [2] 5d e5 [2] 51 ef [2] 46 e4 [2] 5d aa [2] 60 }

  condition:
    any of them
}