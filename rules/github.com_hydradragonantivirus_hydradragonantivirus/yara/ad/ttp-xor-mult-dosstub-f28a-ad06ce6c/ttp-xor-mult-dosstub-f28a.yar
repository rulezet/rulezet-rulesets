rule TTP_XOR_MULT_DOSStub_f28a {
  strings:
    $key_f28a = { a6 e2 [2] d2 fa [2] 95 f8 [2] d2 e9 [2] 9c e5 [2] 90 ef [2] 87 e4 [2] 9c aa [2] a1 }

  condition:
    any of them
}