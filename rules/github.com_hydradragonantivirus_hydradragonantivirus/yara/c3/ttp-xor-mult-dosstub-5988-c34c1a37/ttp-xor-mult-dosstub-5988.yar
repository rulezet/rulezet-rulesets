rule TTP_XOR_MULT_DOSStub_5988 {
  strings:
    $key_5988 = { 0d e0 [2] 79 f8 [2] 3e fa [2] 79 eb [2] 37 e7 [2] 3b ed [2] 2c e6 [2] 37 a8 [2] 0a }

  condition:
    any of them
}