rule TTP_XOR_MULT_DOSStub_b68a {
  strings:
    $key_b68a = { e2 e2 [2] 96 fa [2] d1 f8 [2] 96 e9 [2] d8 e5 [2] d4 ef [2] c3 e4 [2] d8 aa [2] e5 }

  condition:
    any of them
}