rule TTP_XOR_MULT_DOSStub_748a {
  strings:
    $key_748a = { 20 e2 [2] 54 fa [2] 13 f8 [2] 54 e9 [2] 1a e5 [2] 16 ef [2] 01 e4 [2] 1a aa [2] 27 }

  condition:
    any of them
}