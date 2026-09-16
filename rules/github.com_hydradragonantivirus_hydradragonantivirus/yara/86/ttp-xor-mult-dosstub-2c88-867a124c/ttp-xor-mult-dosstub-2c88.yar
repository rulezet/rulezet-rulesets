rule TTP_XOR_MULT_DOSStub_2c88 {
  strings:
    $key_2c88 = { 78 e0 [2] 0c f8 [2] 4b fa [2] 0c eb [2] 42 e7 [2] 4e ed [2] 59 e6 [2] 42 a8 [2] 7f }

  condition:
    any of them
}