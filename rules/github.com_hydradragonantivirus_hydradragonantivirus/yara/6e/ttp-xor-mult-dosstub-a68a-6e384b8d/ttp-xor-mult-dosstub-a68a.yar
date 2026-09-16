rule TTP_XOR_MULT_DOSStub_a68a {
  strings:
    $key_a68a = { f2 e2 [2] 86 fa [2] c1 f8 [2] 86 e9 [2] c8 e5 [2] c4 ef [2] d3 e4 [2] c8 aa [2] f5 }

  condition:
    any of them
}