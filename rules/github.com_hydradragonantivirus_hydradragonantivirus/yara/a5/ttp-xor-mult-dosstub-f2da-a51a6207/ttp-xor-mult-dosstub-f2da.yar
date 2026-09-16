rule TTP_XOR_MULT_DOSStub_f2da {
  strings:
    $key_f2da = { a6 b2 [2] d2 aa [2] 95 a8 [2] d2 b9 [2] 9c b5 [2] 90 bf [2] 87 b4 [2] 9c fa [2] a1 }

  condition:
    any of them
}