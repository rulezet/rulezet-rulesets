rule TTP_XOR_MULT_DOSStub_5bcd {
  strings:
    $key_5bcd = { 0f a5 [2] 7b bd [2] 3c bf [2] 7b ae [2] 35 a2 [2] 39 a8 [2] 2e a3 [2] 35 ed [2] 08 }

  condition:
    any of them
}