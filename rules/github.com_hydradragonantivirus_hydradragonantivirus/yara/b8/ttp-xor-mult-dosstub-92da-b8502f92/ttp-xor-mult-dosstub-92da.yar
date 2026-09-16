rule TTP_XOR_MULT_DOSStub_92da {
  strings:
    $key_92da = { c6 b2 [2] b2 aa [2] f5 a8 [2] b2 b9 [2] fc b5 [2] f0 bf [2] e7 b4 [2] fc fa [2] c1 }

  condition:
    any of them
}