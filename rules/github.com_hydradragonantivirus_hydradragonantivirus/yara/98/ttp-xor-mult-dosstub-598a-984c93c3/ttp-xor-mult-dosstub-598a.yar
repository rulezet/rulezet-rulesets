rule TTP_XOR_MULT_DOSStub_598a {
  strings:
    $key_598a = { 0d e2 [2] 79 fa [2] 3e f8 [2] 79 e9 [2] 37 e5 [2] 3b ef [2] 2c e4 [2] 37 aa [2] 0a }

  condition:
    any of them
}