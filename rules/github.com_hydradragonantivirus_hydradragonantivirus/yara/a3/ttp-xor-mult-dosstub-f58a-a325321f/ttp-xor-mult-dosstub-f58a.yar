rule TTP_XOR_MULT_DOSStub_f58a {
  strings:
    $key_f58a = { a1 e2 [2] d5 fa [2] 92 f8 [2] d5 e9 [2] 9b e5 [2] 97 ef [2] 80 e4 [2] 9b aa [2] a6 }

  condition:
    any of them
}