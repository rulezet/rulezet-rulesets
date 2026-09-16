rule TTP_XOR_MULT_DOSStub_f1da {
  strings:
    $key_f1da = { a5 b2 [2] d1 aa [2] 96 a8 [2] d1 b9 [2] 9f b5 [2] 93 bf [2] 84 b4 [2] 9f fa [2] a2 }

  condition:
    any of them
}