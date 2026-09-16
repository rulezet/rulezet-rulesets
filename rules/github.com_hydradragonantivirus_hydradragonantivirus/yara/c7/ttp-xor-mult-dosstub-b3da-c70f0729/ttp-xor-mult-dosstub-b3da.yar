rule TTP_XOR_MULT_DOSStub_b3da {
  strings:
    $key_b3da = { e7 b2 [2] 93 aa [2] d4 a8 [2] 93 b9 [2] dd b5 [2] d1 bf [2] c6 b4 [2] dd fa [2] e0 }

  condition:
    any of them
}