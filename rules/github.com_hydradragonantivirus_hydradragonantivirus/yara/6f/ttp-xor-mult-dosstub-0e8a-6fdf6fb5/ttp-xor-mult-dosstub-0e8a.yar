rule TTP_XOR_MULT_DOSStub_0e8a {
  strings:
    $key_0e8a = { 5a e2 [2] 2e fa [2] 69 f8 [2] 2e e9 [2] 60 e5 [2] 6c ef [2] 7b e4 [2] 60 aa [2] 5d }

  condition:
    any of them
}