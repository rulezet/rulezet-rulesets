rule TTP_XOR_MULT_DOSStub_908a {
  strings:
    $key_908a = { c4 e2 [2] b0 fa [2] f7 f8 [2] b0 e9 [2] fe e5 [2] f2 ef [2] e5 e4 [2] fe aa [2] c3 }

  condition:
    any of them
}