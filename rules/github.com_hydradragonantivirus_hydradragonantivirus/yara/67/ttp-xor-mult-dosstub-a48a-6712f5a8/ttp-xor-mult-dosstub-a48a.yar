rule TTP_XOR_MULT_DOSStub_a48a {
  strings:
    $key_a48a = { f0 e2 [2] 84 fa [2] c3 f8 [2] 84 e9 [2] ca e5 [2] c6 ef [2] d1 e4 [2] ca aa [2] f7 }

  condition:
    any of them
}