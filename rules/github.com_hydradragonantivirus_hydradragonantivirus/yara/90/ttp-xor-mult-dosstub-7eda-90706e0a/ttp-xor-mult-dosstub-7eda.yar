rule TTP_XOR_MULT_DOSStub_7eda {
  strings:
    $key_7eda = { 2a b2 [2] 5e aa [2] 19 a8 [2] 5e b9 [2] 10 b5 [2] 1c bf [2] 0b b4 [2] 10 fa [2] 2d }

  condition:
    any of them
}