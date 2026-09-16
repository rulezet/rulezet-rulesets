rule TTP_XOR_MULT_DOSStub_5c88 {
  strings:
    $key_5c88 = { 08 e0 [2] 7c f8 [2] 3b fa [2] 7c eb [2] 32 e7 [2] 3e ed [2] 29 e6 [2] 32 a8 [2] 0f }

  condition:
    any of them
}