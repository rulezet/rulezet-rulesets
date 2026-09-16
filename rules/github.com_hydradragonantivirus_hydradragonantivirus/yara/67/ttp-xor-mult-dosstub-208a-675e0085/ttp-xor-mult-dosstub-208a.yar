rule TTP_XOR_MULT_DOSStub_208a {
  strings:
    $key_208a = { 74 e2 [2] 00 fa [2] 47 f8 [2] 00 e9 [2] 4e e5 [2] 42 ef [2] 55 e4 [2] 4e aa [2] 73 }

  condition:
    any of them
}