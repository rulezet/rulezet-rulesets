rule TTP_XOR_MULT_DOSStub_b28a {
  strings:
    $key_b28a = { e6 e2 [2] 92 fa [2] d5 f8 [2] 92 e9 [2] dc e5 [2] d0 ef [2] c7 e4 [2] dc aa [2] e1 }

  condition:
    any of them
}