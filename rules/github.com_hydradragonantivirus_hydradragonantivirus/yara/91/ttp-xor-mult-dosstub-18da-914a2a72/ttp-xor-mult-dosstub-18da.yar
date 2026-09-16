rule TTP_XOR_MULT_DOSStub_18da {
  strings:
    $key_18da = { 4c b2 [2] 38 aa [2] 7f a8 [2] 38 b9 [2] 76 b5 [2] 7a bf [2] 6d b4 [2] 76 fa [2] 4b }

  condition:
    any of them
}