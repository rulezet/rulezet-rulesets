rule TTP_XOR_MULT_DOSStub_e6da {
  strings:
    $key_e6da = { b2 b2 [2] c6 aa [2] 81 a8 [2] c6 b9 [2] 88 b5 [2] 84 bf [2] 93 b4 [2] 88 fa [2] b5 }

  condition:
    any of them
}