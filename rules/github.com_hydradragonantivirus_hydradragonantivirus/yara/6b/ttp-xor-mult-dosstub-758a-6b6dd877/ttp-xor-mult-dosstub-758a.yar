rule TTP_XOR_MULT_DOSStub_758a {
  strings:
    $key_758a = { 21 e2 [2] 55 fa [2] 12 f8 [2] 55 e9 [2] 1b e5 [2] 17 ef [2] 00 e4 [2] 1b aa [2] 26 }

  condition:
    any of them
}