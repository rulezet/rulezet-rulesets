rule TTP_XOR_MULT_DOSStub_4dda {
  strings:
    $key_4dda = { 19 b2 [2] 6d aa [2] 2a a8 [2] 6d b9 [2] 23 b5 [2] 2f bf [2] 38 b4 [2] 23 fa [2] 1e }

  condition:
    any of them
}