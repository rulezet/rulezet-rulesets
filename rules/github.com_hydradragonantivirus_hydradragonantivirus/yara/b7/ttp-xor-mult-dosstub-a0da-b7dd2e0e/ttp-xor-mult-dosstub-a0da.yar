rule TTP_XOR_MULT_DOSStub_a0da {
  strings:
    $key_a0da = { f4 b2 [2] 80 aa [2] c7 a8 [2] 80 b9 [2] ce b5 [2] c2 bf [2] d5 b4 [2] ce fa [2] f3 }

  condition:
    any of them
}