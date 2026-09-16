rule TTP_XOR_MULT_DOSStub_e2da {
  strings:
    $key_e2da = { b6 b2 [2] c2 aa [2] 85 a8 [2] c2 b9 [2] 8c b5 [2] 80 bf [2] 97 b4 [2] 8c fa [2] b1 }

  condition:
    any of them
}