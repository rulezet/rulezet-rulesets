rule TTP_XOR_MULT_DOSStub_f5da {
  strings:
    $key_f5da = { a1 b2 [2] d5 aa [2] 92 a8 [2] d5 b9 [2] 9b b5 [2] 97 bf [2] 80 b4 [2] 9b fa [2] a6 }

  condition:
    any of them
}