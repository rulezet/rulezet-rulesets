rule TTP_XOR_MULT_DOSStub_878a {
  strings:
    $key_878a = { d3 e2 [2] a7 fa [2] e0 f8 [2] a7 e9 [2] e9 e5 [2] e5 ef [2] f2 e4 [2] e9 aa [2] d4 }

  condition:
    any of them
}