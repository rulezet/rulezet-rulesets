rule TTP_XOR_MULT_DOSStub_7a8a {
  strings:
    $key_7a8a = { 2e e2 [2] 5a fa [2] 1d f8 [2] 5a e9 [2] 14 e5 [2] 18 ef [2] 0f e4 [2] 14 aa [2] 29 }

  condition:
    any of them
}