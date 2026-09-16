rule TTP_XOR_MULT_DOSStub_928a {
  strings:
    $key_928a = { c6 e2 [2] b2 fa [2] f5 f8 [2] b2 e9 [2] fc e5 [2] f0 ef [2] e7 e4 [2] fc aa [2] c1 }

  condition:
    any of them
}