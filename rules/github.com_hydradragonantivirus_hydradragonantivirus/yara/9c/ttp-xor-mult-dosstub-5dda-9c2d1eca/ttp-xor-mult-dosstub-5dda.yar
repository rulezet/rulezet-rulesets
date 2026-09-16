rule TTP_XOR_MULT_DOSStub_5dda {
  strings:
    $key_5dda = { 09 b2 [2] 7d aa [2] 3a a8 [2] 7d b9 [2] 33 b5 [2] 3f bf [2] 28 b4 [2] 33 fa [2] 0e }

  condition:
    any of them
}