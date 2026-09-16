rule TTP_XOR_MULT_DOSStub_a28a {
  strings:
    $key_a28a = { f6 e2 [2] 82 fa [2] c5 f8 [2] 82 e9 [2] cc e5 [2] c0 ef [2] d7 e4 [2] cc aa [2] f1 }

  condition:
    any of them
}