rule TTP_XOR_MULT_DOSStub_5e8a {
  strings:
    $key_5e8a = { 0a e2 [2] 7e fa [2] 39 f8 [2] 7e e9 [2] 30 e5 [2] 3c ef [2] 2b e4 [2] 30 aa [2] 0d }

  condition:
    any of them
}