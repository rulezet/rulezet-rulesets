rule TTP_XOR_MULT_DOSStub_7cda {
  strings:
    $key_7cda = { 28 b2 [2] 5c aa [2] 1b a8 [2] 5c b9 [2] 12 b5 [2] 1e bf [2] 09 b4 [2] 12 fa [2] 2f }

  condition:
    any of them
}