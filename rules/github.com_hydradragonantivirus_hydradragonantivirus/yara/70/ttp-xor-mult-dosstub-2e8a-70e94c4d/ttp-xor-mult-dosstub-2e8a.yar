rule TTP_XOR_MULT_DOSStub_2e8a {
  strings:
    $key_2e8a = { 7a e2 [2] 0e fa [2] 49 f8 [2] 0e e9 [2] 40 e5 [2] 4c ef [2] 5b e4 [2] 40 aa [2] 7d }

  condition:
    any of them
}