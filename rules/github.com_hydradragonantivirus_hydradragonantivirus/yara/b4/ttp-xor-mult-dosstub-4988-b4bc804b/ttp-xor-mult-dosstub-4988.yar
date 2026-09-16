rule TTP_XOR_MULT_DOSStub_4988 {
  strings:
    $key_4988 = { 1d e0 [2] 69 f8 [2] 2e fa [2] 69 eb [2] 27 e7 [2] 2b ed [2] 3c e6 [2] 27 a8 [2] 1a }

  condition:
    any of them
}