rule TTP_XOR_MULT_DOSStub_298a {
  strings:
    $key_298a = { 7d e2 [2] 09 fa [2] 4e f8 [2] 09 e9 [2] 47 e5 [2] 4b ef [2] 5c e4 [2] 47 aa [2] 7a }

  condition:
    any of them
}