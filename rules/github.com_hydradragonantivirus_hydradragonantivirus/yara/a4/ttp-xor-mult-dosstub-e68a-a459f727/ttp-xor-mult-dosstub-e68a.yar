rule TTP_XOR_MULT_DOSStub_e68a {
  strings:
    $key_e68a = { b2 e2 [2] c6 fa [2] 81 f8 [2] c6 e9 [2] 88 e5 [2] 84 ef [2] 93 e4 [2] 88 aa [2] b5 }

  condition:
    any of them
}