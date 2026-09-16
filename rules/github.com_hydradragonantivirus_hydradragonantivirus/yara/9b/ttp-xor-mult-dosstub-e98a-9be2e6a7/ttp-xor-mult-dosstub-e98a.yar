rule TTP_XOR_MULT_DOSStub_e98a {
  strings:
    $key_e98a = { bd e2 [2] c9 fa [2] 8e f8 [2] c9 e9 [2] 87 e5 [2] 8b ef [2] 9c e4 [2] 87 aa [2] ba }

  condition:
    any of them
}