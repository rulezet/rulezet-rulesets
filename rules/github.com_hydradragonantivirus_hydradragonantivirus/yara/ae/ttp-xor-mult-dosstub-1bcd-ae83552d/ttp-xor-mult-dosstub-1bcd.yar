rule TTP_XOR_MULT_DOSStub_1bcd {
  strings:
    $key_1bcd = { 4f a5 [2] 3b bd [2] 7c bf [2] 3b ae [2] 75 a2 [2] 79 a8 [2] 6e a3 [2] 75 ed [2] 48 }

  condition:
    any of them
}