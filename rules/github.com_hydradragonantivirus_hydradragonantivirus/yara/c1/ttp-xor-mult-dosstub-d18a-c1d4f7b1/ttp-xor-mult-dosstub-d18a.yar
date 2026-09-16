rule TTP_XOR_MULT_DOSStub_d18a {
  strings:
    $key_d18a = { 85 e2 [2] f1 fa [2] b6 f8 [2] f1 e9 [2] bf e5 [2] b3 ef [2] a4 e4 [2] bf aa [2] 82 }

  condition:
    any of them
}