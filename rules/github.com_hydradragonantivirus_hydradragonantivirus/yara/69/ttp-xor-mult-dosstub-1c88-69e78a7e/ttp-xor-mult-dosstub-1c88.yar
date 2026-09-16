rule TTP_XOR_MULT_DOSStub_1c88 {
  strings:
    $key_1c88 = { 48 e0 [2] 3c f8 [2] 7b fa [2] 3c eb [2] 72 e7 [2] 7e ed [2] 69 e6 [2] 72 a8 [2] 4f }

  condition:
    any of them
}