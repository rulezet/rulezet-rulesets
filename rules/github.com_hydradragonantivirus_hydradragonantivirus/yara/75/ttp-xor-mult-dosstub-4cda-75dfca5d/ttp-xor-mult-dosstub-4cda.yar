rule TTP_XOR_MULT_DOSStub_4cda {
  strings:
    $key_4cda = { 18 b2 [2] 6c aa [2] 2b a8 [2] 6c b9 [2] 22 b5 [2] 2e bf [2] 39 b4 [2] 22 fa [2] 1f }

  condition:
    any of them
}