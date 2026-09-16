rule TTP_XOR_MULT_DOSStub_3c8a {
  strings:
    $key_3c8a = { 68 e2 [2] 1c fa [2] 5b f8 [2] 1c e9 [2] 52 e5 [2] 5e ef [2] 49 e4 [2] 52 aa [2] 6f }

  condition:
    any of them
}