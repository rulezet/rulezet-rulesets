rule TTP_XOR_MULT_DOSStub_d38a {
  strings:
    $key_d38a = { 87 e2 [2] f3 fa [2] b4 f8 [2] f3 e9 [2] bd e5 [2] b1 ef [2] a6 e4 [2] bd aa [2] 80 }

  condition:
    any of them
}