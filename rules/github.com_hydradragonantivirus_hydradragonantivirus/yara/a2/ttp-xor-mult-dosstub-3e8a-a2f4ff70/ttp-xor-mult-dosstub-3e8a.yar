rule TTP_XOR_MULT_DOSStub_3e8a {
  strings:
    $key_3e8a = { 6a e2 [2] 1e fa [2] 59 f8 [2] 1e e9 [2] 50 e5 [2] 5c ef [2] 4b e4 [2] 50 aa [2] 6d }

  condition:
    any of them
}