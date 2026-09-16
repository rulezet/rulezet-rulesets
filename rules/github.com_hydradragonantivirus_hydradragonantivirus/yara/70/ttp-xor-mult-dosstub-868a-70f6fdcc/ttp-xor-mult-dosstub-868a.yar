rule TTP_XOR_MULT_DOSStub_868a {
  strings:
    $key_868a = { d2 e2 [2] a6 fa [2] e1 f8 [2] a6 e9 [2] e8 e5 [2] e4 ef [2] f3 e4 [2] e8 aa [2] d5 }

  condition:
    any of them
}