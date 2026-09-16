rule TTP_XOR_MULT_DOSStub_a6da {
  strings:
    $key_a6da = { f2 b2 [2] 86 aa [2] c1 a8 [2] 86 b9 [2] c8 b5 [2] c4 bf [2] d3 b4 [2] c8 fa [2] f5 }

  condition:
    any of them
}