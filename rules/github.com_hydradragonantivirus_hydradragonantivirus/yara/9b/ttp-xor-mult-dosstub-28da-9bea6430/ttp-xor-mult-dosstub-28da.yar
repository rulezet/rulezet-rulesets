rule TTP_XOR_MULT_DOSStub_28da {
  strings:
    $key_28da = { 7c b2 [2] 08 aa [2] 4f a8 [2] 08 b9 [2] 46 b5 [2] 4a bf [2] 5d b4 [2] 46 fa [2] 7b }

  condition:
    any of them
}