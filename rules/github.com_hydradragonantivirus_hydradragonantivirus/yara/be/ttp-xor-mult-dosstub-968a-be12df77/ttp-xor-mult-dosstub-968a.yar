rule TTP_XOR_MULT_DOSStub_968a {
  strings:
    $key_968a = { c2 e2 [2] b6 fa [2] f1 f8 [2] b6 e9 [2] f8 e5 [2] f4 ef [2] e3 e4 [2] f8 aa [2] c5 }

  condition:
    any of them
}