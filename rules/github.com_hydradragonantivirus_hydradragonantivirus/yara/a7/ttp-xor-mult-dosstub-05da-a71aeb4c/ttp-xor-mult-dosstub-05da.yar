rule TTP_XOR_MULT_DOSStub_05da {
  strings:
    $key_05da = { 51 b2 [2] 25 aa [2] 62 a8 [2] 25 b9 [2] 6b b5 [2] 67 bf [2] 70 b4 [2] 6b fa [2] 56 }

  condition:
    any of them
}