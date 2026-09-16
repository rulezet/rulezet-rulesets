rule TTP_XOR_MULT_DOSStub_1c8a {
  strings:
    $key_1c8a = { 48 e2 [2] 3c fa [2] 7b f8 [2] 3c e9 [2] 72 e5 [2] 7e ef [2] 69 e4 [2] 72 aa [2] 4f }

  condition:
    any of them
}