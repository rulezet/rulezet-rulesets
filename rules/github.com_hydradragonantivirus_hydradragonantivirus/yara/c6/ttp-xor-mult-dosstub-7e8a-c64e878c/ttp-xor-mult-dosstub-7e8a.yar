rule TTP_XOR_MULT_DOSStub_7e8a {
  strings:
    $key_7e8a = { 2a e2 [2] 5e fa [2] 19 f8 [2] 5e e9 [2] 10 e5 [2] 1c ef [2] 0b e4 [2] 10 aa [2] 2d }

  condition:
    any of them
}