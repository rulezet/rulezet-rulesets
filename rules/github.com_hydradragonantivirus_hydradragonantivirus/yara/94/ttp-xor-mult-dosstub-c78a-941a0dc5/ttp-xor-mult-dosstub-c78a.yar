rule TTP_XOR_MULT_DOSStub_c78a {
  strings:
    $key_c78a = { 93 e2 [2] e7 fa [2] a0 f8 [2] e7 e9 [2] a9 e5 [2] a5 ef [2] b2 e4 [2] a9 aa [2] 94 }

  condition:
    any of them
}