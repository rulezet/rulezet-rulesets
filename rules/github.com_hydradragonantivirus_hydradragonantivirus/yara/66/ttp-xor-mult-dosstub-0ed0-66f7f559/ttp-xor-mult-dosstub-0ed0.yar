rule TTP_XOR_MULT_DOSStub_0ed0 {
  strings:
    $key_0ed0 = { 5a b8 [2] 2e a0 [2] 69 a2 [2] 2e b3 [2] 60 bf [2] 6c b5 [2] 7b be [2] 60 f0 [2] 5d }

  condition:
    any of them
}