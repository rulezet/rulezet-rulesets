rule TTP_XOR_MULT_DOSStub_b38a {
  strings:
    $key_b38a = { e7 e2 [2] 93 fa [2] d4 f8 [2] 93 e9 [2] dd e5 [2] d1 ef [2] c6 e4 [2] dd aa [2] e0 }

  condition:
    any of them
}