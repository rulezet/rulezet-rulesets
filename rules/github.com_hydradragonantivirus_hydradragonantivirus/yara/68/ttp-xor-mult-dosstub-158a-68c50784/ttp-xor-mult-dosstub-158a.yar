rule TTP_XOR_MULT_DOSStub_158a {
  strings:
    $key_158a = { 41 e2 [2] 35 fa [2] 72 f8 [2] 35 e9 [2] 7b e5 [2] 77 ef [2] 60 e4 [2] 7b aa [2] 46 }

  condition:
    any of them
}