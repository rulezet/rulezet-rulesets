rule TTP_XOR_MULT_DOSStub_738a {
  strings:
    $key_738a = { 27 e2 [2] 53 fa [2] 14 f8 [2] 53 e9 [2] 1d e5 [2] 11 ef [2] 06 e4 [2] 1d aa [2] 20 }

  condition:
    any of them
}