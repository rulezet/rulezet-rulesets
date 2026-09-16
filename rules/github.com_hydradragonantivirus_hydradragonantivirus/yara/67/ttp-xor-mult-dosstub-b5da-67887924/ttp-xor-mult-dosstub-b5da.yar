rule TTP_XOR_MULT_DOSStub_b5da {
  strings:
    $key_b5da = { e1 b2 [2] 95 aa [2] d2 a8 [2] 95 b9 [2] db b5 [2] d7 bf [2] c0 b4 [2] db fa [2] e6 }

  condition:
    any of them
}