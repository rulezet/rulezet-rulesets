rule TTP_XOR_MULT_DOSStub_b4da {
  strings:
    $key_b4da = { e0 b2 [2] 94 aa [2] d3 a8 [2] 94 b9 [2] da b5 [2] d6 bf [2] c1 b4 [2] da fa [2] e7 }

  condition:
    any of them
}