rule TTP_XOR_MULT_DOSStub_958a {
  strings:
    $key_958a = { c1 e2 [2] b5 fa [2] f2 f8 [2] b5 e9 [2] fb e5 [2] f7 ef [2] e0 e4 [2] fb aa [2] c6 }

  condition:
    any of them
}