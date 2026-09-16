rule TTP_XOR_MULT_DOSStub_4eda {
  strings:
    $key_4eda = { 1a b2 [2] 6e aa [2] 29 a8 [2] 6e b9 [2] 20 b5 [2] 2c bf [2] 3b b4 [2] 20 fa [2] 1d }

  condition:
    any of them
}