rule TTP_XOR_MULT_DOSStub_838a {
  strings:
    $key_838a = { d7 e2 [2] a3 fa [2] e4 f8 [2] a3 e9 [2] ed e5 [2] e1 ef [2] f6 e4 [2] ed aa [2] d0 }

  condition:
    any of them
}