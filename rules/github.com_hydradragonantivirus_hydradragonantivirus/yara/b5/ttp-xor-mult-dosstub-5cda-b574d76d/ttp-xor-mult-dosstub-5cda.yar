rule TTP_XOR_MULT_DOSStub_5cda {
  strings:
    $key_5cda = { 08 b2 [2] 7c aa [2] 3b a8 [2] 7c b9 [2] 32 b5 [2] 3e bf [2] 29 b4 [2] 32 fa [2] 0f }

  condition:
    any of them
}