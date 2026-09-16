rule TTP_XOR_MULT_DOSStub_e3da {
  strings:
    $key_e3da = { b7 b2 [2] c3 aa [2] 84 a8 [2] c3 b9 [2] 8d b5 [2] 81 bf [2] 96 b4 [2] 8d fa [2] b0 }

  condition:
    any of them
}