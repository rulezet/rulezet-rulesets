rule TTP_XOR_MULT_DOSStub_7bcd {
  strings:
    $key_7bcd = { 2f a5 [2] 5b bd [2] 1c bf [2] 5b ae [2] 15 a2 [2] 19 a8 [2] 0e a3 [2] 15 ed [2] 28 }

  condition:
    any of them
}