rule TTP_XOR_MULT_DOSStub_2bcd {
  strings:
    $key_2bcd = { 7f a5 [2] 0b bd [2] 4c bf [2] 0b ae [2] 45 a2 [2] 49 a8 [2] 5e a3 [2] 45 ed [2] 78 }

  condition:
    any of them
}