rule TTP_XOR_MULT_DOSStub_6c88 {
  strings:
    $key_6c88 = { 38 e0 [2] 4c f8 [2] 0b fa [2] 4c eb [2] 02 e7 [2] 0e ed [2] 19 e6 [2] 02 a8 [2] 3f }

  condition:
    any of them
}