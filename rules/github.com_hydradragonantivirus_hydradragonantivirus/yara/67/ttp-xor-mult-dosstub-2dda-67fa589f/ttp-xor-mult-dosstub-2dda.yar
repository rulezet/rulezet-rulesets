rule TTP_XOR_MULT_DOSStub_2dda {
  strings:
    $key_2dda = { 79 b2 [2] 0d aa [2] 4a a8 [2] 0d b9 [2] 43 b5 [2] 4f bf [2] 58 b4 [2] 43 fa [2] 7e }

  condition:
    any of them
}