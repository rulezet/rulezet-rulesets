rule TTP_XOR_MULT_DOSStub_b6da {
  strings:
    $key_b6da = { e2 b2 [2] 96 aa [2] d1 a8 [2] 96 b9 [2] d8 b5 [2] d4 bf [2] c3 b4 [2] d8 fa [2] e5 }

  condition:
    any of them
}