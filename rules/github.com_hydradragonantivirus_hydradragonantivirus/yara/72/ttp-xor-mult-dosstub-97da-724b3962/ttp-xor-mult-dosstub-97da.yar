rule TTP_XOR_MULT_DOSStub_97da {
  strings:
    $key_97da = { c3 b2 [2] b7 aa [2] f0 a8 [2] b7 b9 [2] f9 b5 [2] f5 bf [2] e2 b4 [2] f9 fa [2] c4 }

  condition:
    any of them
}