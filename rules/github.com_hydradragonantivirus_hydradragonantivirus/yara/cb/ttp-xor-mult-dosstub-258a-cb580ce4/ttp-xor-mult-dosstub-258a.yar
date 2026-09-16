rule TTP_XOR_MULT_DOSStub_258a {
  strings:
    $key_258a = { 71 e2 [2] 05 fa [2] 42 f8 [2] 05 e9 [2] 4b e5 [2] 47 ef [2] 50 e4 [2] 4b aa [2] 76 }

  condition:
    any of them
}