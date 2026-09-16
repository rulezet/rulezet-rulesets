rule TTP_XOR_MULT_DOSStub_398c {
  strings:
    $key_398c = { 6d e4 [2] 19 fc [2] 5e fe [2] 19 ef [2] 57 e3 [2] 5b e9 [2] 4c e2 [2] 57 ac [2] 6a }

  condition:
    any of them
}