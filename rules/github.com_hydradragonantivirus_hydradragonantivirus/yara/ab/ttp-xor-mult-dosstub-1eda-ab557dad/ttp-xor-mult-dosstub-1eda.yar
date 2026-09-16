rule TTP_XOR_MULT_DOSStub_1eda {
  strings:
    $key_1eda = { 4a b2 [2] 3e aa [2] 79 a8 [2] 3e b9 [2] 70 b5 [2] 7c bf [2] 6b b4 [2] 70 fa [2] 4d }

  condition:
    any of them
}