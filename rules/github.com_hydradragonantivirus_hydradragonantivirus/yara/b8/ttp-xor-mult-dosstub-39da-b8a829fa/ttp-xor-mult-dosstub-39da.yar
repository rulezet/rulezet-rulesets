rule TTP_XOR_MULT_DOSStub_39da {
  strings:
    $key_39da = { 6d b2 [2] 19 aa [2] 5e a8 [2] 19 b9 [2] 57 b5 [2] 5b bf [2] 4c b4 [2] 57 fa [2] 6a }

  condition:
    any of them
}