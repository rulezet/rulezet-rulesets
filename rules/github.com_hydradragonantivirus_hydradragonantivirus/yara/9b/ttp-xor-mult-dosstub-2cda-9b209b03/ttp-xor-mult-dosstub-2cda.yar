rule TTP_XOR_MULT_DOSStub_2cda {
  strings:
    $key_2cda = { 78 b2 [2] 0c aa [2] 4b a8 [2] 0c b9 [2] 42 b5 [2] 4e bf [2] 59 b4 [2] 42 fa [2] 7f }

  condition:
    any of them
}