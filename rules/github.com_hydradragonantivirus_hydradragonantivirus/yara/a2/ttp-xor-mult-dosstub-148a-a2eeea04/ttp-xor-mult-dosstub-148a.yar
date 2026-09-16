rule TTP_XOR_MULT_DOSStub_148a {
  strings:
    $key_148a = { 40 e2 [2] 34 fa [2] 73 f8 [2] 34 e9 [2] 7a e5 [2] 76 ef [2] 61 e4 [2] 7a aa [2] 47 }

  condition:
    any of them
}