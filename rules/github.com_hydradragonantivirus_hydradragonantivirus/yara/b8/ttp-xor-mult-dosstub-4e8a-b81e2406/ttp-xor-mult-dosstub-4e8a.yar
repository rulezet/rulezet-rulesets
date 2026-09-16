rule TTP_XOR_MULT_DOSStub_4e8a {
  strings:
    $key_4e8a = { 1a e2 [2] 6e fa [2] 29 f8 [2] 6e e9 [2] 20 e5 [2] 2c ef [2] 3b e4 [2] 20 aa [2] 1d }

  condition:
    any of them
}