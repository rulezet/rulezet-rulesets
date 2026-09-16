rule TTP_XOR_MULT_DOSStub_178a {
  strings:
    $key_178a = { 43 e2 [2] 37 fa [2] 70 f8 [2] 37 e9 [2] 79 e5 [2] 75 ef [2] 62 e4 [2] 79 aa [2] 44 }

  condition:
    any of them
}