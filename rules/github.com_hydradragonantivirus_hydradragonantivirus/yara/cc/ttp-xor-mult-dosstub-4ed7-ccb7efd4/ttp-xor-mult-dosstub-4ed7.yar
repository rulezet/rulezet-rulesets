rule TTP_XOR_MULT_DOSStub_4ed7 {
  strings:
    $key_4ed7 = { 1a bf [2] 6e a7 [2] 29 a5 [2] 6e b4 [2] 20 b8 [2] 2c b2 [2] 3b b9 [2] 20 f7 [2] 1d }

  condition:
    any of them
}