rule TTP_XOR_MULT_DOSStub_59da {
  strings:
    $key_59da = { 0d b2 [2] 79 aa [2] 3e a8 [2] 79 b9 [2] 37 b5 [2] 3b bf [2] 2c b4 [2] 37 fa [2] 0a }

  condition:
    any of them
}