rule TTP_XOR_MULT_DOSStub_108a {
  strings:
    $key_108a = { 44 e2 [2] 30 fa [2] 77 f8 [2] 30 e9 [2] 7e e5 [2] 72 ef [2] 65 e4 [2] 7e aa [2] 43 }

  condition:
    any of them
}