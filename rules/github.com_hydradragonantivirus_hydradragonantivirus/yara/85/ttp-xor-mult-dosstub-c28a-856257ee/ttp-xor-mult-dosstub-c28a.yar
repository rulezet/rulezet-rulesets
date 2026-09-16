rule TTP_XOR_MULT_DOSStub_c28a {
  strings:
    $key_c28a = { 96 e2 [2] e2 fa [2] a5 f8 [2] e2 e9 [2] ac e5 [2] a0 ef [2] b7 e4 [2] ac aa [2] 91 }

  condition:
    any of them
}