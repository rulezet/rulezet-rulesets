rule TTP_XOR_MULT_DOSStub_69da {
  strings:
    $key_69da = { 3d b2 [2] 49 aa [2] 0e a8 [2] 49 b9 [2] 07 b5 [2] 0b bf [2] 1c b4 [2] 07 fa [2] 3a }

  condition:
    any of them
}