rule TTP_XOR_MULT_DOSStub_09da {
  strings:
    $key_09da = { 5d b2 [2] 29 aa [2] 6e a8 [2] 29 b9 [2] 67 b5 [2] 6b bf [2] 7c b4 [2] 67 fa [2] 5a }

  condition:
    any of them
}