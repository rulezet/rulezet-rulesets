rule TTP_XOR_MULT_DOSStub_d78a {
  strings:
    $key_d78a = { 83 e2 [2] f7 fa [2] b0 f8 [2] f7 e9 [2] b9 e5 [2] b5 ef [2] a2 e4 [2] b9 aa [2] 84 }

  condition:
    any of them
}