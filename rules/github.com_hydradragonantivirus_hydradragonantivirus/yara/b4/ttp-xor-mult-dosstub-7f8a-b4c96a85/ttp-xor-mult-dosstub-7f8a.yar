rule TTP_XOR_MULT_DOSStub_7f8a {
  strings:
    $key_7f8a = { 2b e2 [2] 5f fa [2] 18 f8 [2] 5f e9 [2] 11 e5 [2] 1d ef [2] 0a e4 [2] 11 aa [2] 2c }

  condition:
    any of them
}