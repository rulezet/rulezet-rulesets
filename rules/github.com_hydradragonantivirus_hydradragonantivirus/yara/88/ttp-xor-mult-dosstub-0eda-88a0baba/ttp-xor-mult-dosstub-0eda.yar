rule TTP_XOR_MULT_DOSStub_0eda {
  strings:
    $key_0eda = { 5a b2 [2] 2e aa [2] 69 a8 [2] 2e b9 [2] 60 b5 [2] 6c bf [2] 7b b4 [2] 60 fa [2] 5d }

  condition:
    any of them
}