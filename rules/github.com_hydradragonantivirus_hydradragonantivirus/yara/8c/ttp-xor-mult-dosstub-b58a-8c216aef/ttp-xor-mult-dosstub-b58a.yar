rule TTP_XOR_MULT_DOSStub_b58a {
  strings:
    $key_b58a = { e1 e2 [2] 95 fa [2] d2 f8 [2] 95 e9 [2] db e5 [2] d7 ef [2] c0 e4 [2] db aa [2] e6 }

  condition:
    any of them
}