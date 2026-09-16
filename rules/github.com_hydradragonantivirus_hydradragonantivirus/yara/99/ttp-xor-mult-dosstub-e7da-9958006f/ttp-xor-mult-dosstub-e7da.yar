rule TTP_XOR_MULT_DOSStub_e7da {
  strings:
    $key_e7da = { b3 b2 [2] c7 aa [2] 80 a8 [2] c7 b9 [2] 89 b5 [2] 85 bf [2] 92 b4 [2] 89 fa [2] b4 }

  condition:
    any of them
}