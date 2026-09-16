rule TTP_XOR_MULT_DOSStub_4bcd {
  strings:
    $key_4bcd = { 1f a5 [2] 6b bd [2] 2c bf [2] 6b ae [2] 25 a2 [2] 29 a8 [2] 3e a3 [2] 25 ed [2] 18 }

  condition:
    any of them
}