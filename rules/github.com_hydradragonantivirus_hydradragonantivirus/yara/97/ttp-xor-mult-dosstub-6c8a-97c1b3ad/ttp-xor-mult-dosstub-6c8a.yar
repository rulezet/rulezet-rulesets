rule TTP_XOR_MULT_DOSStub_6c8a {
  strings:
    $key_6c8a = { 38 e2 [2] 4c fa [2] 0b f8 [2] 4c e9 [2] 02 e5 [2] 0e ef [2] 19 e4 [2] 02 aa [2] 3f }

  condition:
    any of them
}