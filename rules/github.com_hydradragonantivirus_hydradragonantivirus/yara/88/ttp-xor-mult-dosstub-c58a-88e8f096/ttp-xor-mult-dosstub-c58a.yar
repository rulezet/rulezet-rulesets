rule TTP_XOR_MULT_DOSStub_c58a {
  strings:
    $key_c58a = { 91 e2 [2] e5 fa [2] a2 f8 [2] e5 e9 [2] ab e5 [2] a7 ef [2] b0 e4 [2] ab aa [2] 96 }

  condition:
    any of them
}