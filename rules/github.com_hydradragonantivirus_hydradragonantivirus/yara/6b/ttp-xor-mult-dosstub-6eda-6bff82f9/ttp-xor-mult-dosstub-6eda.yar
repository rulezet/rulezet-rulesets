rule TTP_XOR_MULT_DOSStub_6eda {
  strings:
    $key_6eda = { 3a b2 [2] 4e aa [2] 09 a8 [2] 4e b9 [2] 00 b5 [2] 0c bf [2] 1b b4 [2] 00 fa [2] 3d }

  condition:
    any of them
}