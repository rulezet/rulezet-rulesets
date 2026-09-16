rule TTP_XOR_MULT_DOSStub_c68a {
  strings:
    $key_c68a = { 92 e2 [2] e6 fa [2] a1 f8 [2] e6 e9 [2] a8 e5 [2] a4 ef [2] b3 e4 [2] a8 aa [2] 95 }

  condition:
    any of them
}