rule TTP_XOR_MULT_DOSStub_5ed1 {
  strings:
    $key_5ed1 = { 0a b9 [2] 7e a1 [2] 39 a3 [2] 7e b2 [2] 30 be [2] 3c b4 [2] 2b bf [2] 30 f1 [2] 0d }

  condition:
    any of them
}