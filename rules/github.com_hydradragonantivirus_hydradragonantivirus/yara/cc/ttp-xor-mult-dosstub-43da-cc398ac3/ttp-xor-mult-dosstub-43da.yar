rule TTP_XOR_MULT_DOSStub_43da {
  strings:
    $key_43da = { 17 b2 [2] 63 aa [2] 24 a8 [2] 63 b9 [2] 2d b5 [2] 21 bf [2] 36 b4 [2] 2d fa [2] 10 }

  condition:
    any of them
}