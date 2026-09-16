rule TTP_XOR_MULT_DOSStub_4e88 {
  strings:
    $key_4e88 = { 1a e0 [2] 6e f8 [2] 29 fa [2] 6e eb [2] 20 e7 [2] 2c ed [2] 3b e6 [2] 20 a8 [2] 1d }

  condition:
    any of them
}