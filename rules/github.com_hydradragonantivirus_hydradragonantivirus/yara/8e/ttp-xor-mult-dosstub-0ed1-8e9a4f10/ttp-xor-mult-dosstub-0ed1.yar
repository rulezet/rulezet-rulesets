rule TTP_XOR_MULT_DOSStub_0ed1 {
  strings:
    $key_0ed1 = { 5a b9 [2] 2e a1 [2] 69 a3 [2] 2e b2 [2] 60 be [2] 6c b4 [2] 7b bf [2] 60 f1 [2] 5d }

  condition:
    any of them
}