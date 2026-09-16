rule TTP_XOR_MULT_DOSStub_d48a {
  strings:
    $key_d48a = { 80 e2 [2] f4 fa [2] b3 f8 [2] f4 e9 [2] ba e5 [2] b6 ef [2] a1 e4 [2] ba aa [2] 87 }

  condition:
    any of them
}