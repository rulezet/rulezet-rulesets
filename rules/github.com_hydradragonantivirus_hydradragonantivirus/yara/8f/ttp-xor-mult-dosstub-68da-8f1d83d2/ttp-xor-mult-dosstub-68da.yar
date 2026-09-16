rule TTP_XOR_MULT_DOSStub_68da {
  strings:
    $key_68da = { 3c b2 [2] 48 aa [2] 0f a8 [2] 48 b9 [2] 06 b5 [2] 0a bf [2] 1d b4 [2] 06 fa [2] 3b }

  condition:
    any of them
}