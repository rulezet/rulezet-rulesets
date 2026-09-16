rule TTP_XOR_MULT_DOSStub_e58a {
  strings:
    $key_e58a = { b1 e2 [2] c5 fa [2] 82 f8 [2] c5 e9 [2] 8b e5 [2] 87 ef [2] 90 e4 [2] 8b aa [2] b6 }

  condition:
    any of them
}